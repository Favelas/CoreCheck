'use strict';

const { reportsStore } = require('../store/reports.store');
const { AppError } = require('../errors/AppError');

/**
 * POST /api/reports → 201
 * Requiere req.validatedReport (middleware validateReportBody).
 */
function createReport(req, res) {
  const report = reportsStore.create(req.validatedReport);
  res.status(201).json(report);
}

/** GET /api/reports → 200 envelope { total, data } */
function listReports(_req, res) {
  res.status(200).json(reportsStore.list());
}

/** GET /api/reports/:id → 200 | 404 */
function getReportById(req, res) {
  const { id } = req.params;
  const report = reportsStore.findById(id);

  if (!report) {
    throw new AppError(
      'NOT_FOUND',
      `No existe un reporte con id "${id}".`,
      404
    );
  }

  res.status(200).json(report);
}

module.exports = {
  createReport,
  listReports,
  getReportById
};
