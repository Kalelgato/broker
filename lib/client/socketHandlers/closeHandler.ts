import { LoadedClientOpts } from '../../common/types/options';
import { log as logger } from '../../logs/logger';

export const closeHandler = (
  clientOps: LoadedClientOpts,
  identifyingMetadata,
) => {
  // logger.warn(
  //   {
  //     url: clientOps.config.brokerServerUrl,
  //     token: clientOps.config.brokerToken,
  //   },
  //   'websocket connection to the broker server was closed',
  // );
  logger.warn(
    {
      url: clientOps.config.brokerServerUrl,
      token: clientOps.config.universalBrokerEnabled
        ? identifyingMetadata.integrationId
        : clientOps.config.brokerToken,
    },
    'websocket connection to the broker server was closed',
  );
};
