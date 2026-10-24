const mongoose = require('mongoose');

// Project Schema
const projectSchema = new mongoose.Schema({
 name: { 
    type: String, 
    required: true, 
    unique: true 
}, 
// Project names must be unique
 description: { 
    type: String 
}, 
// Optional field for project details
 createdAt: { 
    type: Date, 
    default: Date.now 
}
});
module.exports = mongoose.model('Project', projectSchema);