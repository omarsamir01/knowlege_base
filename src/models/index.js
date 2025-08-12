// After all models are imported
const { Department, Employee } = models;

// Department belongs to an Employee (manager)
Department.belongsTo(Employee, {
  foreignKey: 'employee_id',
  as: 'manager'
});

// Employee can manage one department
Employee.hasOne(Department, {
  foreignKey: 'employee_id',
  as: 'managed_department'
});