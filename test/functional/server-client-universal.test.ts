import path from 'path';
import { axiosClient } from '../setup/axios-client';
import { BrokerClient, closeBrokerClient } from '../setup/broker-client';
import {
  BrokerServer,
  closeBrokerServer,
  createBrokerServer,
  waitForUniversalBrokerClientsConnection,
} from '../setup/broker-server';
import { TestWebServer, createTestWebServer } from '../setup/test-web-server';
import { createUniversalBrokerClient } from '../setup/broker-universal-client';

const fixtures = path.resolve(__dirname, '..', 'fixtures');
const serverAccept = path.join(fixtures, 'server', 'filters.json');
const clientAccept = path.join(fixtures, 'client', 'filters.json');
describe('proxy requests originating from behind the broker server', () => {
  let tws: TestWebServer;
  let bs: BrokerServer;
  let bc: BrokerClient;

  const spyLogWarn = jest
    .spyOn(require('bunyan').prototype, 'warn')
    .mockImplementation((value) => {
      return value;
    });

  beforeAll(async () => {
    const PORT = 9999;
    tws = await createTestWebServer();

    bs = await createBrokerServer({ filters: serverAccept, port: PORT });

    process.env.SNYK_BROKER_SERVER_UNIVERSAL_CONFIG_ENABLED = 'true';
    process.env.UNIVERSAL_BROKER_ENABLED = 'true';
    process.env.SERVICE_ENV = 'universaltest';
    process.env.BROKER_TOKEN_1 = 'brokertoken1';
    process.env.BROKER_TOKEN_2 = 'brokertoken2';
    process.env.GITHUB_TOKEN = 'ghtoken';
    process.env.GITLAB_TOKEN = 'gltoken';

    process.env.SNYK_BROKER_CLIENT_CONFIGURATION__common__default__BROKER_SERVER_URL = `http://localhost:${bs.port}`;
    process.env.SNYK_FILTER_RULES_PATHS__github = clientAccept;
    process.env.SNYK_FILTER_RULES_PATHS__gitlab = clientAccept;
    bc = await createUniversalBrokerClient();
    await waitForUniversalBrokerClientsConnection(bs, 2);
  });

  afterEach(async () => {
    spyLogWarn.mockReset();
  });
  afterAll(async () => {
    spyLogWarn.mockReset();
    await tws.server.close();
    await closeBrokerClient(bc);
    await closeBrokerServer(bs);
    delete process.env.BROKER_SERVER_URL;
    delete process.env.SNYK_BROKER_SERVER_UNIVERSAL_CONFIG_ENABLED;
    delete process.env
      .SNYK_BROKER_CLIENT_CONFIGURATION__common__default__BROKER_SERVER_URL;
  });

  it('successfully broker GET', async () => {
    const response = await axiosClient.get(
      `http://localhost:${bs.port}/broker/${process.env.BROKER_TOKEN_1}/echo-param/xyz`,
    );

    const response2 = await axiosClient.get(
      `http://localhost:${bs.port}/broker/${process.env.BROKER_TOKEN_2}/echo-param/xyz`,
    );
    expect(response.status).toEqual(200);
    expect(response.data).toEqual('xyz');
    expect(response2.status).toEqual(200);
    expect(response2.data).toEqual('xyz');
  });

  it('successfully warn logs requests without x-snyk-broker-type header', async () => {
    const response = await axiosClient.get(
      `http://localhost:${bs.port}/broker/${process.env.BROKER_TOKEN_1}/echo-param/xyz`,
    );

    const response2 = await axiosClient.get(
      `http://localhost:${bs.port}/broker/${process.env.BROKER_TOKEN_2}/echo-param/xyz`,
    );
    expect(response.status).toEqual(200);
    expect(response.data).toEqual('xyz');

    expect(response2.status).toEqual(200);
    expect(response2.data).toEqual('xyz');

    expect(spyLogWarn).toHaveBeenCalledTimes(2);
    expect(spyLogWarn).toHaveBeenCalledWith(
      expect.any(Object),
      'Error: Request does not contain the x-snyk-broker-type header',
    );
  });
});
