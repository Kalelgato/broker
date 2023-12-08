import primus from 'primus';
import { Request, Response } from 'express';
import version from '../../common/utils/version';
import { WebSocketConnection } from '../types/client';
import { maskToken } from '../../common/utils/token';

interface healthcheckData {
  ok: boolean;
  identifier?: string;
  websocketConnectionOpen: boolean;
  brokerServerUrl: string;
  version: string;
  transport: string;
}

export const healthCheckHandler =
  // io is available in res.locals.websocket
  (req: Request, res: Response) => {
    const websocketConnsArray = res.locals
      .websocketConnections as WebSocketConnection[];
    const data: healthcheckData[] = [];
    const statuses: Array<number> = [];
    for (let i = 0; i < websocketConnsArray.length; i++) {
      const isConnOpen =
        websocketConnsArray[i].readyState === primus.Spark.OPEN;
      statuses.push(isConnOpen ? 200 : 500);
      const tunnelData = {
        ok: isConnOpen,
        websocketConnectionOpen: isConnOpen,
        brokerServerUrl: websocketConnsArray[i].url.href,
        version,
        transport: websocketConnsArray[i].socket.transport.name,
      };
      if (websocketConnsArray[i].identifier) {
        tunnelData['identifier'] = maskToken(
          websocketConnsArray[i].identifier ?? '',
        );
        tunnelData['friendlyName'] = websocketConnsArray[i].friendlyName ?? '';
      }
      data.push(tunnelData);
    }
    // healthcheck state depends on websocket connection status
    // value of primus.Spark.OPEN means the websocket connection is open
    return res
      .status(statuses.some((status) => status == 500) ? 500 : 200)
      .json(data.length == 1 ? data[0] : data); // So we don't break current setups
  };
