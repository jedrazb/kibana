/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { compact, uniq } from 'lodash';
import { ElasticsearchClient } from '@kbn/core-elasticsearch-server';
import { EntityV2 } from '@kbn/entities-schema';
import { ESQLSearchResponse } from '@kbn/es-types';
import { EntitySource } from '.';

function getLatestDate(date1?: string, date2?: string) {
  if (!date1 && !date2) return;

  return new Date(
    Math.max(date1 ? Date.parse(date1) : 0, date2 ? Date.parse(date2) : 0)
  ).toISOString();
}

function mergeEntities(metadataFields: string[], entity1: EntityV2, entity2: EntityV2): EntityV2 {
  const merged: EntityV2 = { ...entity1 };

  const latestTimestamp = getLatestDate(
    entity1['entity.last_seen_timestamp'],
    entity2['entity.last_seen_timestamp']
  );
  if (latestTimestamp) {
    merged['entity.last_seen_timestamp'] = latestTimestamp;
  }

  for (const [key, value] of Object.entries(entity2).filter(([_key]) =>
    metadataFields.includes(_key)
  )) {
    if (merged[key]) {
      merged[key] = uniq([
        ...(Array.isArray(merged[key]) ? merged[key] : [merged[key]]),
        ...(Array.isArray(value) ? value : [value]),
      ]);
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

export function mergeEntitiesList(sources: EntitySource[], entities: EntityV2[]): EntityV2[] {
  const metadataFields = uniq(
    sources.flatMap((source) => compact([source.timestamp_field, ...source.metadata_fields]))
  );
  const instances: { [key: string]: EntityV2 } = {};

  for (let i = 0; i < entities.length; i++) {
    const entity = entities[i];
    const id = entity['entity.id'];

    if (instances[id]) {
      instances[id] = mergeEntities(metadataFields, instances[id], entity);
    } else {
      instances[id] = entity;
    }
  }

  return Object.values(instances);
}

export async function runESQLQuery<T>({
  esClient,
  query,
}: {
  esClient: ElasticsearchClient;
  query: string;
}): Promise<T[]> {
  const esqlResponse = (await esClient.esql.query(
    {
      query,
      format: 'json',
    },
    { querystring: { drop_null_columns: true } }
  )) as unknown as ESQLSearchResponse;

  const documents = esqlResponse.values.map((row) =>
    row.reduce<Record<string, any>>((acc, value, index) => {
      const column = esqlResponse.columns[index];

      if (!column) {
        return acc;
      }

      // Removes the type suffix from the column name
      const name = column.name.replace(/\.(text|keyword)$/, '');
      if (!acc[name]) {
        acc[name] = value;
      }

      return acc;
    }, {})
  ) as T[];

  return documents;
}
