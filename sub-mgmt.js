import { StringCodec } from 'nats';
import { auth } from './ad.js';

export async function handleAuthSubscription(sub) {
  const sc = StringCodec();
  console.log(`listening for ${sub.getSubject()} requests`);
  for await (const m of sub) {
    const request = m.subject;
    const payload = JSON.parse(sc.decode(m.data));
    const [user, pass] = payload;
    console.info(`[auth] #${sub.getProcessed()} handling ${request}`);
    try {
      const data = { user: await auth(user, pass), status: 'ok' };
      m.respond(sc.encode(JSON.stringify(data)));
    } catch (error) {
      m.respond(sc.encode(JSON.stringify({ error: error, status: 'error' })));
    }
  }
  console.log(`subscription ${sub.getSubject()} drained.`);
}
