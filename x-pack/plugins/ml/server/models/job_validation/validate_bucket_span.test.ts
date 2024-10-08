/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { SKIP_BUCKET_SPAN_ESTIMATION } from '@kbn/ml-validators';

import type { JobValidationMessage } from '../../../common/constants/messages';
// @ts-ignore
import { validateBucketSpan } from './validate_bucket_span';

// farequote2017 snapshot snapshot mock search response
// it returns a mock for the response of PolledDataChecker's search request
// to get an aggregation of non_empty_buckets with an interval of 1m.
// this allows us to test bucket span estimation.
import mockFareQuoteSearchResponse from './__mocks__/mock_farequote_search_response.json';

// it_ops_app_logs 2017 snapshot mock search response
// sparse data with a low number of buckets
import mockItSearchResponse from './__mocks__/mock_it_search_response.json';

// mock mlClusterClientFactory
const mlClusterClientFactory = (mockSearchResponse: any) => {
  const callAs = () => {
    return new Promise((resolve) => {
      resolve({ body: mockSearchResponse });
    });
  };
  return {
    asCurrentUser: callAs,
    asInternalUser: callAs,
  };
};

describe('ML - validateBucketSpan', () => {
  it('called without arguments', (done) => {
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse)).then(
      () => done(new Error('Promise should not resolve for this test without job argument.')),
      () => done()
    );
  });

  it('called with non-valid job argument #1, missing datafeed_config', (done) => {
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), {}).then(
      () => done(new Error('Promise should not resolve for this test without valid job argument.')),
      () => done()
    );
  });

  it('called with non-valid job argument #2, missing datafeed_config.indices', (done) => {
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), {
      datafeed_config: {},
    }).then(
      () => done(new Error('Promise should not resolve for this test without valid job argument.')),
      () => done()
    );
  });

  it('called with non-valid job argument #3, missing data_description', (done) => {
    const job = { datafeed_config: { indices: [] } };
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), job).then(
      () => done(new Error('Promise should not resolve for this test without valid job argument.')),
      () => done()
    );
  });

  it('called with non-valid job argument #4, missing data_description.time_field', (done) => {
    const job = { datafeed_config: { indices: [] }, data_description: {} };
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), job).then(
      () => done(new Error('Promise should not resolve for this test without valid job argument.')),
      () => done()
    );
  });

  it('called with non-valid job argument #5, missing analysis_config.influencers', (done) => {
    const job = {
      datafeed_config: { indices: [] },
      data_description: { time_field: '@timestamp' },
    };
    validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), job).then(
      () => done(new Error('Promise should not resolve for this test without valid job argument.')),
      () => done()
    );
  });

  it('called without duration argument', () => {
    const job = {
      analysis_config: { detectors: [], influencers: [] },
      data_description: { time_field: '@timestamp' },
      datafeed_config: { indices: [] },
    };

    return validateBucketSpan(mlClusterClientFactory(mockFareQuoteSearchResponse), job).then(
      (messages: JobValidationMessage[]) => {
        const ids = messages.map((m) => m.id);
        expect(ids).toStrictEqual([]);
      }
    );
  });

  const getJobConfig = (bucketSpan: string) => ({
    analysis_config: {
      bucket_span: bucketSpan,
      detectors: [] as Array<{ function?: string }>,
      influencers: [],
    },
    data_description: { time_field: '@timestamp' },
    datafeed_config: { indices: [] },
  });

  it('minimal config to return a success message', () => {
    const job = getJobConfig('15m');
    const duration = { start: 0, end: 1 };

    return validateBucketSpan(
      mlClusterClientFactory(mockFareQuoteSearchResponse),
      job,
      duration
    ).then((messages: JobValidationMessage[]) => {
      const ids = messages.map((m) => m.id);
      expect(ids).toStrictEqual(['success_bucket_span']);
    });
  });

  it('bucket span > 1d', () => {
    const job = getJobConfig('2d');
    const duration = { start: 0, end: 1 };

    return validateBucketSpan(
      mlClusterClientFactory(mockFareQuoteSearchResponse),
      job,
      duration
    ).then((messages: JobValidationMessage[]) => {
      const ids = messages.map((m) => m.id);
      expect(ids).toStrictEqual(['bucket_span_high']);
    });
  });

  if (SKIP_BUCKET_SPAN_ESTIMATION) {
    return;
  }

  const testBucketSpan = (
    bucketSpan: string,
    mockSearchResponse: any,
    test: (ids: string[]) => void
  ) => {
    const job = getJobConfig(bucketSpan);
    job.analysis_config.detectors.push({
      function: 'count',
    });

    return validateBucketSpan(mlClusterClientFactory(mockSearchResponse), job, {}).then(
      (messages: JobValidationMessage[]) => {
        const ids = messages.map((m) => m.id);
        test(ids);
      }
    );
  };

  it('farequote count detector, bucket span estimation matches 15m', () => {
    return testBucketSpan('15m', mockFareQuoteSearchResponse, (ids) => {
      expect(ids).toStrictEqual(['success_bucket_span']);
    });
  });

  it('farequote count detector, bucket span estimation does not match 1m', () => {
    return testBucketSpan('1m', mockFareQuoteSearchResponse, (ids) => {
      expect(ids).toStrictEqual(['bucket_span_estimation_mismatch']);
    });
  });

  // the current implementation of bucket span estimation returns 6h
  // for the 'it_ops_app_logs' dataset. it's a sparse dataset which returns
  // not many non-empty buckets. future work on bucket estimation and sparsity validation
  // should result in a lower bucket span estimation.
  it('it_ops_app_logs count detector, bucket span estimation matches 6h', () => {
    return testBucketSpan('6h', mockItSearchResponse, (ids) => {
      expect(ids).toStrictEqual(['success_bucket_span']);
    });
  });
});
