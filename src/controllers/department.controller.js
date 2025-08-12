const departmentService = require('../services/department.service');
const ApiResponse = require('../utils/apiResponse');

class DepartmentController {
  async createDepartment(req, res, next) {
    try {
      const { name, description, employee_id } = req.body;
      const department = await departmentService.createDepartment(
        name, 
        description, 
        employee_id
      );
      ApiResponse.created(res, 'Department created successfully', department);
    } catch (error) {
      next(error);
    }
  }

  async getAllDepartments(req, res, next) {
    try {
      const departments = await departmentService.getAllDepartments();
      ApiResponse.success(res, 'Departments retrieved successfully', departments);
    } catch (error) {
      next(error);
    }
  }

  async getDepartment(req, res, next) {
    try {
      const department = await departmentService.getDepartmentById(req.params.id);
      ApiResponse.success(res, 'Department retrieved successfully', department);
    } catch (error) {
      next(error);
    }
  }

  async updateDepartment(req, res, next) {
    try {
      const department = await departmentService.updateDepartment(
        req.params.id, 
        req.body
      );
      ApiResponse.success(res, 'Department updated successfully', department);
    } catch (error) {
      next(error);
    }
  }

  async deleteDepartment(req, res, next) {
    try {
      const result = await departmentService.deleteDepartment(req.params.id);
      ApiResponse.success(res, result.message);
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new DepartmentController();