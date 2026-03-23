const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
    url: { 
        type: String, 
        required: true 
    },
    riskScore: { 
        type: Number, 
        required: true 
    },
    riskLevel: { 
        type: String, 
        required: true 
    },
    vtMalicious: { 
        type: Number, 
        default: 0 
    },
    vtTotal: { 
        type: Number, 
        default: 0 
    },
    googleFlagged: { 
        type: Boolean, 
        default: false 
    },
    timestamp: { 
        type: Date, 
        default: Date.now 
    }
});

module.exports = mongoose.model('Scan', scanSchema);