const { Model, DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  class Department extends Model {
    static associate(models) {
      Department.belongsTo(models.Employee, {
        foreignKey: 'employee_id',
        as: 'manager'
      });
    }
  }
  
  Department.init({
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    name: {
      type: DataTypes.STRING(255),
      allowNull: false,
      unique: true
    },
    description: {
      type: DataTypes.TEXT,
      allowNull: true
    },
    employee_id: {
      type: DataTypes.INTEGER,
      allowNull: true,
      references: {
        model: 'employees',
        key: 'id'
      }
    },
    created_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    },
    updated_at: {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    }
  }, {
    sequelize,
    modelName: 'Department',
    tableName: 'departments',
    timestamps: false,
    underscored: true,
    hooks: {
      beforeUpdate: (department) => {
        department.updated_at = new Date();
      }
    }
  });

  return Department;
};