/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { FtrProviderContext } from '../../../ftr_provider_context';

export default function ({ getService }: FtrProviderContext) {
  const svlCommonApi = getService('svlCommonApi');
  const supertest = getService('supertest');

  describe('security/features', function () {
    it('route access disabled', async () => {
      const { body, status } = await supertest
        .get('/internal/security/_check_security_features')
        .set(svlCommonApi.getInternalRequestHeader());
      svlCommonApi.assertApiNotFound(body, status);
    });
  });
}
