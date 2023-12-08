import path from 'path';
import { axiosClient } from '../setup/axios-client';
import {
  BrokerClient,
  closeBrokerClient,
  createBrokerClient,
} from '../setup/broker-client';
import {
  BrokerServer,
  closeBrokerServer,
  createBrokerServer,
  waitForBrokerClientConnection,
} from '../setup/broker-server';
import { TestWebServer, createTestWebServer } from '../setup/test-web-server';

const fixtures = path.resolve(__dirname, '..', 'fixtures');
const clientAccept = path.join(fixtures, 'client', 'filters.json');
const emptyServerAccept = path.join(fixtures, 'server', 'empty_filters.json');

describe('no filters broker', () => {
  let tws: TestWebServer;
  let bs: BrokerServer;
  let bc: BrokerClient;
  let brokerToken: string;

  beforeAll(async () => {
    const PORT = 9999;
    process.env.BROKER_SERVER_URL = `http://localhost:${PORT}`;
    tws = await createTestWebServer();

    bs = await createBrokerServer({ filters: emptyServerAccept });

    bc = await createBrokerClient({
      brokerServerUrl: `http://localhost:${bs.port}`,
      brokerToken: '12345',
      filters: clientAccept,
    });
    ({ brokerToken } = await waitForBrokerClientConnection(bs));
  });

  afterAll(async () => {
    await tws.server.close();
    await closeBrokerClient(bc);
    await closeBrokerServer(bs);
    delete process.env.BROKER_SERVER_URL;
  });

  it('successfully broker with no filter should reject', async () => {
    const url = `http://localhost:${bs.port}/broker/${brokerToken}/echo-body`;
    const response = await axiosClient.post(url, { test: 'body' });

    expect(response.status).toEqual(401);
    expect(response.data).toStrictEqual({
      message: 'blocked',
      reason: 'Request does not match any accept rule, blocking HTTP request',
      url: '/echo-body',
    });
  });
});
