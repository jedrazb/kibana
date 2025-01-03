/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { setTimeout as setTimeoutAsync } from 'timers/promises';
import type { Cookie } from 'tough-cookie';
import { parse as parseCookie } from 'tough-cookie';

import expect from '@kbn/expect';
import {
  getSAMLRequestId,
  getSAMLResponse,
} from '@kbn/security-api-integration-helpers/saml/saml_tools';
import type { AuthenticationProvider } from '@kbn/security-plugin/common';
import { adminTestUser } from '@kbn/test';

import type { FtrProviderContext } from '../../ftr_provider_context';

export default function ({ getService }: FtrProviderContext) {
  const supertest = getService('supertestWithoutAuth');
  const esSupertest = getService('esSupertest');
  const es = getService('es');
  const esDeleteAllIndices = getService('esDeleteAllIndices');
  const config = getService('config');
  const retry = getService('retry');
  const log = getService('log');
  const randomness = getService('randomness');
  const { username: basicUsername, password: basicPassword } = adminTestUser;
  const kibanaServerConfig = config.get('servers.kibana');

  async function checkSessionCookie(
    sessionCookie: Cookie,
    username: string,
    provider: AuthenticationProvider
  ) {
    log.debug(`Verifying session cookie for ${username}.`);
    const apiResponse = await supertest
      .get('/internal/security/me')
      .set('kbn-xsrf', 'xxx')
      .set('Cookie', sessionCookie.cookieString())
      .expect(200);
    log.debug(`Session cookie for ${username} is valid.`);

    expect(apiResponse.body.username).to.be(username);
    expect(apiResponse.body.authentication_provider).to.eql(provider);

    return Array.isArray(apiResponse.headers['set-cookie'])
      ? parseCookie(apiResponse.headers['set-cookie'][0])!
      : undefined;
  }

  async function getNumberOfSessionDocuments() {
    await es.indices.refresh({ index: '.kibana_security_session*' });
    return (
      // @ts-expect-error doesn't handle total as number
      (await es.search({ index: '.kibana_security_session*' })).hits.total.value as number
    );
  }

  async function loginWithSAML(providerName: string) {
    const handshakeResponse = await supertest
      .post('/internal/security/login')
      .set('kbn-xsrf', 'xxx')
      .send({ providerType: 'saml', providerName, currentURL: '' })
      .expect(200);

    const authenticationResponse = await supertest
      .post('/api/security/saml/callback')
      .set('kbn-xsrf', 'xxx')
      .set('Cookie', parseCookie(handshakeResponse.headers['set-cookie'][0])!.cookieString())
      .send({
        SAMLResponse: await getSAMLResponse({
          destination: `http://localhost:${kibanaServerConfig.port}/api/security/saml/callback`,
          sessionIndex: String(randomness.naturalNumber()),
          inResponseTo: await getSAMLRequestId(handshakeResponse.body.location),
        }),
      })
      .expect(302);

    const cookie = parseCookie(authenticationResponse.headers['set-cookie'][0])!;
    await checkSessionCookie(cookie, 'a@b.c', { type: 'saml', name: providerName });
    return cookie;
  }

  async function runCleanupTaskSoon() {
    // In most cases, an error would mean the task is currently running so let's run it again
    await retry.tryForTime(30000, async () => {
      await supertest
        .post('/session/_run_cleanup')
        .set('kbn-xsrf', 'xxx')
        .auth(adminTestUser.username, adminTestUser.password)
        .send()
        .expect(200);
    });
  }

  async function addESDebugLoggingSettings() {
    const addLogging = {
      persistent: {
        'logger.org.elasticsearch.xpack.security.authc': 'debug',
      },
    };
    await esSupertest.put('/_cluster/settings').send(addLogging).expect(200);
  }

  describe('Session Idle cleanup', () => {
    beforeEach(async () => {
      await es.cluster.health({ index: '.kibana_security_session*', wait_for_status: 'green' });
      await addESDebugLoggingSettings();
      await esDeleteAllIndices('.kibana_security_session*');
    });

    it('should properly clean up session expired because of idle timeout', async function () {
      this.timeout(100000);

      log.debug(`Log in as ${basicUsername} using ${basicPassword} password.`);
      const response = await supertest
        .post('/internal/security/login')
        .set('kbn-xsrf', 'xxx')
        .send({
          providerType: 'basic',
          providerName: 'basic1',
          currentURL: '/',
          params: { username: basicUsername, password: basicPassword },
        })
        .expect(200);

      const sessionCookie = parseCookie(response.headers['set-cookie'][0])!;
      await checkSessionCookie(sessionCookie, basicUsername, { type: 'basic', name: 'basic1' });
      expect(await getNumberOfSessionDocuments()).to.be(1);

      // Poke the background task to run
      await runCleanupTaskSoon();
      log.debug('Waiting for cleanup job to run...');
      // Cleanup routine runs every 20s, and idle timeout threshold is three times larger than 10s
      // idle timeout (so, 30s). We just triggered the cleanup, so we'll wait for 40s to make sure
      // cleanup routine runs after the idle timeout threshold is exceeded. Then we'll wait for a
      // correct response.
      await setTimeoutAsync(40000);
      await retry.tryForTime(20000, async () => {
        // Session info is removed from the index and cookie isn't valid anymore
        expect(await getNumberOfSessionDocuments()).to.be(0);
      });

      log.debug(`Authenticating as ${basicUsername} with invalid session cookie.`);
      await supertest
        .get('/internal/security/me')
        .set('kbn-xsrf', 'xxx')
        .set('Cookie', sessionCookie.cookieString())
        .expect(401);
    });

    it('should properly clean up session expired because of idle timeout when providers override global session config', async function () {
      this.timeout(100000);

      const [samlDisableSessionCookie, samlOverrideSessionCookie, samlFallbackSessionCookie] =
        await Promise.all([
          loginWithSAML('saml_disable'),
          loginWithSAML('saml_override'),
          loginWithSAML('saml_fallback'),
        ]);

      const response = await supertest
        .post('/internal/security/login')
        .set('kbn-xsrf', 'xxx')
        .send({
          providerType: 'basic',
          providerName: 'basic1',
          currentURL: '/',
          params: { username: basicUsername, password: basicPassword },
        })
        .expect(200);

      const basicSessionCookie = parseCookie(response.headers['set-cookie'][0])!;
      await checkSessionCookie(basicSessionCookie, basicUsername, {
        type: 'basic',
        name: 'basic1',
      });
      expect(await getNumberOfSessionDocuments()).to.be(4);

      // Poke the background task to run
      await runCleanupTaskSoon();
      log.debug('Waiting for cleanup job to run...');
      // Cleanup routine runs every 20s, and idle timeout threshold is three times larger than 10s
      // idle timeout (so, 30s). We just triggered the cleanup, so we'll wait for 40s to make sure
      // cleanup routine runs after the idle timeout threshold is exceeded. Then we'll wait for a
      // correct response.
      await setTimeoutAsync(40000);
      await retry.tryForTime(20000, async () => {
        // Session for basic and SAML that used global session settings should not be valid anymore.
        expect(await getNumberOfSessionDocuments()).to.be(2);
      });

      await supertest
        .get('/internal/security/me')
        .set('kbn-xsrf', 'xxx')
        .set('Cookie', basicSessionCookie.cookieString())
        .expect(401);
      await supertest
        .get('/internal/security/me')
        .set('kbn-xsrf', 'xxx')
        .set('Cookie', samlFallbackSessionCookie.cookieString())
        .expect(401);

      // But sessions for the SAML with overridden and disabled lifespan should still be valid.
      await checkSessionCookie(samlOverrideSessionCookie, 'a@b.c', {
        type: 'saml',
        name: 'saml_override',
      });
      await checkSessionCookie(samlDisableSessionCookie, 'a@b.c', {
        type: 'saml',
        name: 'saml_disable',
      });
    });

    it('should not clean up session if user is active', async function () {
      this.timeout(100000);

      const response = await supertest
        .post('/internal/security/login')
        .set('kbn-xsrf', 'xxx')
        .send({
          providerType: 'basic',
          providerName: 'basic1',
          currentURL: '/',
          params: { username: basicUsername, password: basicPassword },
        })
        .expect(200);

      let sessionCookie = parseCookie(response.headers['set-cookie'][0])!;
      await checkSessionCookie(sessionCookie, basicUsername, { type: 'basic', name: 'basic1' });
      expect(await getNumberOfSessionDocuments()).to.be(1);

      // Run 20 consequent requests with 3s delay, during this time cleanup procedure should run at
      // least twice.
      for (const counter of [...Array(20).keys()]) {
        // Session idle timeout is 10s, let's wait 3s and make a new request that would extend the session.
        await setTimeoutAsync(3000);

        sessionCookie = (await checkSessionCookie(sessionCookie, basicUsername, {
          type: 'basic',
          name: 'basic1',
        }))!;
        log.debug(`Session is still valid after ${(counter + 1) * 3}s`);
      }

      // Session document should still be present.
      expect(await getNumberOfSessionDocuments()).to.be(1);
    });
  });
}
