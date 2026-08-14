'use strict';

const SERVICE_NAME = 'Corecheck API';

function getHealth(_req, res) {
  res.status(200).json({
    status: 'ok',
    service: SERVICE_NAME,
    timestamp: new Date().toISOString()
  });
}

module.exports = { getHealth, SERVICE_NAME };
