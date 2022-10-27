import * as dotenv from 'dotenv';
import { connect } from 'nats';
import {
  handleAuthSubscription,
} from './sub-mgmt.js';

dotenv.config();
async function main() {
  const nc = await connect({ servers: process.env.MQ_SERVER });
  const authsub = nc.subscribe('auth');
  handleAuthSubscription(authsub);

  // wait for the client to close here.
  await nc.closed().then((err) => {
    let m = `connection to ${nc.getServer()} closed`;
    if (err) {
      m = `${m} with an error: ${err.message}`;
    }
    console.log(m);
  });
}

main()
