/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';
import type { demodata } from '../../../canvas_plugin_src/functions/server/demodata';
import { FunctionHelp } from '../function_help';
import { FunctionFactory } from '../../../types';
// eslint-disable-next-line @kbn/imports/no_boundary_crossing
import { DemoRows } from '../../../canvas_plugin_src/functions/server/demodata/demo_rows_types';

export const help: FunctionHelp<FunctionFactory<typeof demodata>> = {
  help: i18n.translate('xpack.canvas.functions.demodataHelpText', {
    defaultMessage:
      'A sample data set that includes project {ci} times with usernames, countries, and run phases.',
    values: {
      ci: 'CI',
    },
  }),
  args: {
    type: i18n.translate('xpack.canvas.functions.demodata.args.typeHelpText', {
      defaultMessage: 'The name of the demo data set to use.',
    }),
  },
};

export const errors = {
  invalidDataSet: (arg: string | null) =>
    new Error(
      i18n.translate('xpack.canvas.functions.demodata.invalidDataSetErrorMessage', {
        defaultMessage: "Invalid data set: ''{arg}'', use ''{ci}'' or ''{shirts}''.",
        values: {
          arg,
          ci: DemoRows.CI,
          shirts: DemoRows.SHIRTS,
        },
      })
    ),
};
