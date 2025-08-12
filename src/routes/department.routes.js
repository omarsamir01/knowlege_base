const express = require('express');
const router = express.Router();
const departmentController = require('../controllers/department.controller');
const authMiddleware = require('../middlewares/auth.middleware');

// Apply authentication middleware to all department routes
router.use(authMiddleware);

// Create a new department
router.post('/', departmentController.createDepartment);

// Get all departments
router.get('/', departmentController.getAllDepartments);

// Get a single department by ID
router.get('/:id', departmentController.getDepartment);

// Update a department
router.put('/:id', departmentController.updateDepartment);

// Delete a department
router.delete('/:id', departmentController.deleteDepartment);

module.exports = router;