require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const { initializeDatabase } = require("./db/db.connect");
const Project = require("./models/project.models.js");
const Tag = require("./models/tag.models");
const Task = require("./models/task.models");
const Team = require("./models/team.models");
const User = require("./models/user.models");

const app = express();
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://fsp-1-assignment-frontend-ten.vercel.app",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// ====================================
// JWT AUTHENTICATION MIDDLEWARE
// ====================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Expect: Authorization: Bearer <token>
  const token =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

  if (!token) {
    return res.status(401).json({
      message: "Access denied. Please provide a token.",
    });
  }

  if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET is missing from .env");
    return res.status(500).json({
      message: "Server configuration error.",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
    if (error) {
      return res.status(401).json({
        message: "Invalid or expired token.",
      });
    }

    // Store authenticated user's information on the request
    req.user = decoded;

    next();
  });
};

// ====================================
// HOME ROUTE (PUBLIC)
// ====================================
app.get("/", (req, res) => {
  res.send("Backend is running!");
});

// ====================================
// SIGNUP API (PUBLIC)
// ====================================
app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      !name.trim() ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Valid name, email, and password are required.",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters long.",
      });
    }

    const normalizedName = name.trim();
    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already registered.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name: normalizedName,
      email: normalizedEmail,
      password: hashedPassword,
    });

    return res.status(201).json({
      message: "User registered successfully.",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
      },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Email is already registered.",
      });
    }

    console.error("Signup error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

// ====================================
// LOGIN API (PUBLIC)
// ====================================
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is missing from .env");
      return res.status(500).json({
        message: "Server configuration error.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail,
    });

    if (!user || !user.password) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: "1d" },
    );

    return res.status(200).json({
      message: "Login successful.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    return res.status(200).json({
      message: "User details fetched successfully.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Get current user error:", error.message);
    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.post("/tasks", authenticateToken, async (req, res) => {
  try {
    const { name, project, team, owners, tags, timeToComplete, status } =
      req.body;

    // 1. Validate required fields
    if (
      typeof name !== "string" ||
      !name.trim() ||
      !project ||
      !team ||
      !Array.isArray(owners) ||
      !Array.isArray(tags) ||
      !Number.isFinite(timeToComplete) ||
      timeToComplete <= 0 ||
      typeof status !== "string" ||
      !status.trim()
    ) {
      return res.status(400).json({
        message: "Please provide valid task details.",
      });
    }

    // 2. Validate MongoDB IDs
    const isValidId = (id) =>
      typeof id === "string" && /^[a-f\d]{24}$/i.test(id);

    if (
      !isValidId(project) ||
      !isValidId(team) ||
      !owners.every(isValidId) ||
      !tags.every(isValidId)
    ) {
      return res.status(400).json({
        message:
          "Project, team, owners, and tags must contain valid MongoDB IDs.",
      });
    }

    // 3. Check that related records exist
    const [projectExists, teamExists, existingOwners, existingTags] =
      await Promise.all([
        Project.findById(project),
        Team.findById(team),
        User.find({ _id: { $in: owners } }).select("_id"),
        Tag.find({ _id: { $in: tags } }).select("_id"),
      ]);

    if (!projectExists) {
      return res.status(404).json({
        message: "Project not found.",
      });
    }

    if (!teamExists) {
      return res.status(404).json({
        message: "Team not found.",
      });
    }

    if (existingOwners.length !== new Set(owners).size) {
      return res.status(404).json({
        message: "One or more owners were not found.",
      });
    }

    if (existingTags.length !== new Set(tags).size) {
      return res.status(404).json({
        message: "One or more tags were not found.",
      });
    }

    // 4. Create the task
    const newTask = await Task.create({
      name: name.trim(),
      project,
      team,
      owners,
      tags,
      timeToComplete,
      status: status.trim(),
    });

    // 5. Return the created task
    return res.status(201).json({
      message: "Task created successfully.",
      task: newTask,
    });
  } catch (error) {
    console.error("Create task error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.get("/tasks", authenticateToken, async (req, res) => {
  try {
    const { team, owner, tags, project, status } = req.query;
    const filter = {};

    const isValidId = (value) =>
      typeof value === "string" && /^[a-f\d]{24}$/i.test(value);

    // Filter by team ID or team name
    if (team) {
      if (isValidId(team)) {
        filter.team = team;
      } else {
        const foundTeam = await Team.findOne({
          name: team,
        });

        if (!foundTeam) {
          return res.status(200).json({ tasks: [] });
        }

        filter.team = foundTeam._id;
      }
    }

    // Filter by owner ID or owner name
    if (owner) {
      if (isValidId(owner)) {
        filter.owners = owner;
      } else {
        const foundOwner = await User.findOne({
          name: owner,
        });

        if (!foundOwner) {
          return res.status(200).json({ tasks: [] });
        }

        filter.owners = foundOwner._id;
      }
    }

    // Filter by project ID or project name
    if (project) {
      if (isValidId(project)) {
        filter.project = project;
      } else {
        const foundProject = await Project.findOne({
          name: project,
        });

        if (!foundProject) {
          return res.status(200).json({ tasks: [] });
        }

        filter.project = foundProject._id;
      }
    }

    // Filter by one or more tags (comma-separated)
    if (tags) {
      const tagValues = tags
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean);

      const tagIds = [];

      for (const tagValue of tagValues) {
        if (isValidId(tagValue)) {
          tagIds.push(tagValue);
        } else {
          const foundTag = await Tag.findOne({
            name: tagValue,
          });

          if (foundTag) {
            tagIds.push(foundTag._id.toString());
          }
        }
      }

      if (tagIds.length === 0) {
        return res.status(200).json({ tasks: [] });
      }

      // Match tasks containing any requested tag
      filter.tags = { $in: tagIds };
    }

    // Filter by status
    if (status) {
      const validStatuses = ["To Do", "In Progress", "Completed", "Blocked"];

      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          message: "Invalid status.",
          validStatuses,
        });
      }

      filter.status = status;
    }

    const tasks = await Task.find(filter)
      .populate("project", "name")
      .populate("team", "name")
      .populate("owners", "name email")
      .sort({ createdAt: -1 });

    return res.status(200).json({
      count: tasks.length,
      tasks,
    });
  } catch (error) {
    console.error("Fetch tasks error:", error);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.post("/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Validate task ID
    if (!/^[a-f\d]{24}$/i.test(id)) {
      return res.status(400).json({ message: "Invalid task ID." });
    }

    // 2. Find the existing task
    const task = await Task.findById(id);

    if (!task) {
      return res.status(404).json({ message: "Task not found." });
    }

    // 3. Allow only these fields to be updated
    const allowedFields = [
      "name",
      "project",
      "team",
      "owners",
      "tags",
      "timeToComplete",
      "status",
    ];

    const fields = Object.keys(req.body);

    if (
      fields.length === 0 ||
      fields.some((field) => !allowedFields.includes(field))
    ) {
      return res.status(400).json({
        message: "Provide valid fields to update.",
      });
    }

    const { name, project, team, owners, tags, timeToComplete, status } =
      req.body;

    // 4. Validate individual fields
    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
      return res.status(400).json({
        message: "Task name cannot be empty.",
      });
    }

    if (
      status !== undefined &&
      !["To Do", "In Progress", "Completed", "Blocked"].includes(status)
    ) {
      return res.status(400).json({
        message: "Invalid task status.",
      });
    }

    if (
      timeToComplete !== undefined &&
      (!Number.isFinite(timeToComplete) || timeToComplete <= 0)
    ) {
      return res.status(400).json({
        message: "timeToComplete must be a positive number.",
      });
    }

    // 5. Validate related documents if their IDs are updated
    const isValidId = (value) =>
      typeof value === "string" && /^[a-f\d]{24}$/i.test(value);

    if (project !== undefined) {
      if (!isValidId(project) || !(await Project.findById(project))) {
        return res.status(400).json({
          message: "Invalid project ID.",
        });
      }
    }

    if (team !== undefined) {
      if (!isValidId(team) || !(await Team.findById(team))) {
        return res.status(400).json({
          message: "Invalid team ID.",
        });
      }
    }

    if (owners !== undefined) {
      if (!Array.isArray(owners) || owners.some((owner) => !isValidId(owner))) {
        return res.status(400).json({
          message: "owners must be an array of valid user IDs.",
        });
      }

      const users = await User.find({ _id: { $in: owners } });

      if (users.length !== new Set(owners).size) {
        return res.status(400).json({
          message: "One or more owners do not exist.",
        });
      }
    }

    if (tags !== undefined) {
      if (!Array.isArray(tags) || tags.some((tag) => !isValidId(tag))) {
        return res.status(400).json({
          message: "tags must be an array of valid tag IDs.",
        });
      }

      const existingTags = await Tag.find({ _id: { $in: tags } });

      if (existingTags.length !== new Set(tags).size) {
        return res.status(400).json({
          message: "One or more tags do not exist.",
        });
      }
    }

    // 6. Update only the fields sent in the request
    for (const field of fields) {
      task[field] = field === "name" ? name.trim() : req.body[field];
    }

    // 7. Save the updated task
    await task.save();

    // 8. Return the updated task with related details
    const updatedTask = await Task.findById(task._id)
      .populate("project", "name")
      .populate("team", "name")
      .populate("owners", "name email");

    return res.status(200).json({
      message: "Task updated successfully.",
      task: updatedTask,
    });
  } catch (error) {
    console.error("Update task error:", error);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.delete("/tasks/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Validate task ID
    if (!/^[a-f\d]{24}$/i.test(id)) {
      return res.status(400).json({
        message: "Invalid task ID.",
      });
    }

    // 2. Find and delete the task
    const deletedTask = await Task.findByIdAndDelete(id);

    // 3. Check if task exists
    if (!deletedTask) {
      return res.status(404).json({
        message: "Task not found.",
      });
    }

    // 4. Send success response
    return res.status(200).json({
      message: "Task deleted successfully.",
      task: deletedTask,
    });
  } catch (error) {
    console.error("Delete task error:", error);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.post("/projects", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    // Validate project name
    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        message: "Project name is required.",
      });
    }

    // Create project
    const newProject = await Project.create({
      name: name.trim(),
      description:
        typeof description === "string" ? description.trim() : undefined,
    });

    return res.status(201).json({
      message: "Project created successfully.",
      project: newProject,
    });
  } catch (error) {
    // Handle duplicate project names
    if (error.code === 11000) {
      return res.status(409).json({
        message: "A project with this name already exists.",
      });
    }

    console.error("Create project error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.get("/projects", authenticateToken, async (req, res) => {
  try {
    // Fetch all projects, newest first
    const projects = await Project.find().sort({ createdAt: -1 });

    return res.status(200).json({
      count: projects.length,
      projects,
    });
  } catch (error) {
    console.error("Fetch projects error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.post("/tags", authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        message: "Tag name is required.",
      });
    }

    const newTag = await Tag.create({
      name: name.trim(),
    });

    return res.status(201).json({
      message: "Tag created successfully.",
      tag: newTag,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "This tag already exists.",
      });
    }

    console.error("Create tag error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.get("/tags", authenticateToken, async (req, res) => {
  try {
    // Fetch all tags, sorted alphabetically
    const tags = await Tag.find().sort({ name: 1 });

    return res.status(200).json({
      count: tags.length,
      tags,
    });
  } catch (error) {
    console.error("Fetch tags error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.post("/teams", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    // Validate team name
    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        message: "Team name is required.",
      });
    }

    // Create team
    const newTeam = await Team.create({
      name: name.trim(),
      description:
        typeof description === "string" ? description.trim() : undefined,
    });

    return res.status(201).json({
      message: "Team created successfully.",
      team: newTeam,
    });
  } catch (error) {
    // Handle duplicate team names
    if (error.code === 11000) {
      return res.status(409).json({
        message: "A team with this name already exists.",
      });
    }

    console.error("Create team error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

app.get("/teams", authenticateToken, async (req, res) => {
  try {
    // Fetch all teams from MongoDB
    const teams = await Team.find().sort({ name: 1 });

    return res.status(200).json({
      count: teams.length,
      teams,
    });
  } catch (error) {
    console.error("Fetch teams error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

// Get tasks completed in the last week
app.get("/report/last-week", authenticateToken, async (req, res) => {
  try {
    const now = new Date();

    const lastWeek = new Date();
    lastWeek.setDate(now.getDate() - 7);

    const tasks = await Task.find({
      status: "Completed",
      updatedAt: {
        $gte: lastWeek,
        $lte: now,
      },
    })
      .populate("project", "name")
      .populate("team", "name")
      .populate("owners", "name email")
      .sort({ updatedAt: -1 });

    return res.status(200).json({
      message: "Last week's completed tasks fetched successfully.",
      count: tasks.length,
      tasks,
    });
  } catch (error) {
    console.error("Last-week report error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

// Get total days of pending work
app.get("/report/pending", authenticateToken, async (req, res) => {
  try {
    const tasks = await Task.find({
      status: { $ne: "Completed" },
    });

    const totalPendingDays = tasks.reduce((total, task) => {
      return total + task.timeToComplete;
    }, 0);

    return res.status(200).json({
      message: "Pending work report fetched successfully.",
      totalPendingDays,
      pendingTasksCount: tasks.length,
    });
  } catch (error) {
    console.error("Pending report error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

// Get completed task counts grouped by team, owner, or project
app.get("/report/closed-tasks", authenticateToken, async (req, res) => {
  try {
    const { by } = req.query;

    if (!["team", "owner", "project"].includes(by)) {
      return res.status(400).json({
        message: "Please provide by=team, by=owner, or by=project.",
      });
    }

    const groupFields = {
      team: "$team",
      owner: "$owners",
      project: "$project",
    };

    const collections = {
      team: Team.collection.name,
      owner: User.collection.name,
      project: Project.collection.name,
    };

    const pipeline = [
      {
        $match: {
          status: "Completed",
        },
      },
    ];

    // Each owner should be counted separately
    if (by === "owner") {
      pipeline.push({ $unwind: "$owners" });
    }

    pipeline.push(
      {
        $group: {
          _id: groupFields[by],
          completedTasks: { $sum: 1 },
        },
      },
      {
        $lookup: {
          from: collections[by],
          localField: "_id",
          foreignField: "_id",
          as: "details",
        },
      },
      {
        $unwind: {
          path: "$details",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 0,
          groupId: "$_id",
          name: "$details.name",
          completedTasks: 1,
        },
      },
      {
        $sort: {
          completedTasks: -1,
        },
      },
    );

    const results = await Task.aggregate(pipeline);

    return res.status(200).json({
      message: "Closed tasks report fetched successfully.",
      groupedBy: by,
      results,
    });
  } catch (error) {
    console.error("Closed tasks report error:", error.message);

    return res.status(500).json({
      message: "Internal server error.",
    });
  }
});

// ====================================
// START SERVER AFTER DATABASE CONNECTION
// ====================================
const startServer = async () => {
  try {
    await initializeDatabase();

    app.listen(5000, () => {
      console.log("Server running on port 5000");
    });
  } catch (error) {
    console.error("Database connection failed:", error.message);
    process.exit(1);
  }
};

startServer();
