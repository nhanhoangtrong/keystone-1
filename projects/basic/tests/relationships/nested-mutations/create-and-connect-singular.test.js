const { Text, Relationship } = require('@keystonejs/fields');
const { resolveAllKeys, mapKeys } = require('@keystonejs/utils');
const cuid = require('cuid');

const { setupServer, graphqlRequest } = require('../../util');

let server;

beforeAll(() => {
  server = setupServer({
    name: `ks5-testdb-${cuid()}`,
    createLists: keystone => {
      keystone.createList('Group', {
        fields: {
          name: { type: Text },
        },
      });

      keystone.createList('Event', {
        fields: {
          title: { type: Text },
          group: { type: Relationship, ref: 'Group' },
        },
      });

      keystone.createList('GroupNoRead', {
        fields: {
          name: { type: Text },
        },
        access: {
          read: () => false,
        },
      });

      keystone.createList('EventToGroupNoRead', {
        fields: {
          title: { type: Text },
          group: { type: Relationship, ref: 'GroupNoRead' },
        },
      });

      keystone.createList('GroupNoCreate', {
        fields: {
          name: { type: Text },
        },
        access: {
          create: () => false,
        },
      });

      keystone.createList('EventToGroupNoCreate', {
        fields: {
          title: { type: Text },
          group: { type: Relationship, ref: 'GroupNoCreate' },
        },
      });
    },
  });

  server.keystone.connect();
});

afterAll(async () => {
  // clean the db
  await resolveAllKeys(mapKeys(server.keystone.adapters, adapter => adapter.dropDatabase()));
  // then shut down
  await resolveAllKeys(
    mapKeys(server.keystone.adapters, adapter => adapter.dropDatabase().then(() => adapter.close()))
  );
});

beforeEach(() =>
  // clean the db
  resolveAllKeys(mapKeys(server.keystone.adapters, adapter => adapter.dropDatabase())));

describe('errors on incomplete data', () => {
  test('when neither id or create data passed', async () => {
    // Create an item that does the linking
    const createEvent = await graphqlRequest({
      server,
      query: `
        mutation {
          createEvent(data: { group: {} }) {
            id
          }
        }
    `,
    });

    expect(createEvent.body).toHaveProperty('data.createEvent', null);
    expect(createEvent.body.errors).toMatchObject([
      {
        name: 'NestedError',
        data: {
          errors: [
            {
              path: ['createEvent', 'group'],
              name: 'ParameterError',
            },
          ],
        },
      },
    ]);
  });

  test('when both id and create data passed', async () => {
    // Create an item that does the linking
    const createEvent = await graphqlRequest({
      server,
      query: `
        mutation {
          createEvent(data: { group: {
            connect: { id: "abc123"},
            create: { name: "foo" }
          } }) {
            id
          }
        }
    `,
    });

    expect(createEvent.body).toHaveProperty('data.createEvent', null);
    expect(createEvent.body.errors).toMatchObject([
      {
        name: 'NestedError',
        data: {
          errors: [
            {
              path: ['createEvent', 'group'],
              name: 'ParameterError',
            },
          ],
        },
      },
    ]);
  });
});
