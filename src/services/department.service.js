const db = require('../models');
const ApiError = require('../utils/apiError');

class DepartmentService {
  async createDepartment(name, description, employeeId) {
    try {
      return await db.Department.create({ 
        name, 
        description, 
        employee_id: employeeId 
      });
    } catch (error) {
      if (error.name === 'SequelizeUniqueConstraintError') {
        throw ApiError.badRequest('Department name already exists');
      }
      throw ApiError.internal('Error creating department');
    }
  }

  async getAllDepartments() {
    return db.Department.findAll({
      include: [{
        model: db.Employee,
        as: 'manager',
        attributes: ['id', 'first_name', 'last_name', 'email']
      }]
    });
  }

  async getDepartmentById(id) {
    const department = await db.Department.findByPk(id, {
      include: [{
        model: db.Employee,
        as: 'manager'
      }]
    });
    
    if (!department) {
      throw ApiError.notFound('Department not found');
    }
    return department;
  }

  async updateDepartment(id, updateData) {
    const department = await this.getDepartmentById(id);
    
    try {
      return await department.update(updateData);
    } catch (error) {
      if (error.name === 'SequelizeUniqueConstraintError') {
        throw ApiError.badRequest('Department name already exists');
      }
      throw ApiError.internal('Error updating department');
    }
  }

  async deleteDepartment(id) {
    const department = await this.getDepartmentById(id);
    
    try {
      await department.destroy();
      return { message: 'Department deleted successfully' };
    } catch (error) {
      throw ApiError.internal('Error deleting department');
    }
  }
}

module.exports = new DepartmentService();