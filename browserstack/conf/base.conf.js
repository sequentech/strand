// SPDX-FileCopyrightText: 2022 Félix Robles <felix@sequentech.io>
//
// SPDX-License-Identifier: AGPL-3.0-only

exports.config = {
  user: 'felixtest_P6cl4FNofZ5',
  key: 'Cuuy52b1oxCySnKrQ8H8',
  updateJob: false,
  exclude: [],
  logLevel: 'warn',
  coloredLogs: true,
  screenshotPath: './errorShots/',
  baseUrl: '',
  waitforTimeout: 100000,
  connectionRetryTimeout: 90000,
  connectionRetryCount: 3,
  hostname: 'hub.browserstack.com',
  services: [['@browserstack/wdio-browserstack-service']],
  before: function () {
    var chai = require('chai');
    global.expect = chai.expect;
    chai.Should();
  },
  framework: 'mocha',
  mochaOpts: {
    ui: 'bdd',
    timeout: 100000
  }
}
