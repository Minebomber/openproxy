import { useEffect, useState } from 'react';
import { Modal } from './Dialogs';
import { post, request } from './api';
import { Button } from './components/ui/button';
import { NativeSelect } from './components/ui/native-select';
import { HeaderTable, BodyView } from './Detail';
import type { Flow, FlowSummary, Notify } from './types';
interface Difference {
  method: string;
  url: string;
  current_id: number | null;
  other_id: number | null;
  result: string;
  fields: string[];
}
interface Pair {
  difference: Difference;
  left: Flow;
  right: Flow;
}
export function CompareDialog({
  flows,
  selected,
  token,
  close,
  notify,
}: {
  flows: FlowSummary[];
  selected: number | null;
  token: string;
  close: () => void;
  notify: Notify;
}) {
  const [left, setLeft] = useState(selected ?? flows[0]?.id ?? 0),
    [right, setRight] = useState(flows.find((flow) => flow.id !== left)?.id ?? 0);
  const [pair, setPair] = useState<Pair | null>(null),
    [session, setSession] = useState<Difference[] | null>(null),
    [phase, setPhase] = useState('response'),
    [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!left || !right) return;
    const controller = new AbortController();
    setPair(null);
    request<Pair>(`flows/${left}/compare?other=${right}`, token, { signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted) setPair(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted) notify(String(error), true);
      });
    return () => controller.abort();
  }, [left, right, token]);
  return (
    <Modal title="Compare exchanges & sessions" close={close} className="breakpoints-dialog">
      <div className="dialog-scroll min-w-0 space-y-4">
        <p>
          Select two exchanges or compare the retained session with a saved native/HAR file.
          Duplicate destinations pair in capture order. Incomplete bodies give an unknown result.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <label>
            Current exchange
            <NativeSelect
              aria-label="Current comparison exchange"
              value={left}
              onChange={(event) => setLeft(Number(event.target.value))}
            >
              {flows.map((flow) => (
                <option key={flow.id} value={flow.id}>
                  #{flow.id} {flow.method} {flow.url.slice(0, 60)}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label>
            Compare to
            <NativeSelect
              aria-label="Other comparison exchange"
              value={right}
              onChange={(event) => setRight(Number(event.target.value))}
            >
              {flows.map((flow) => (
                <option key={flow.id} value={flow.id}>
                  #{flow.id} {flow.method} {flow.url.slice(0, 60)}
                </option>
              ))}
            </NativeSelect>
          </label>
        </div>
        <label className="flex-row! items-center">
          Compare session file
          <input
            id="compare-session-file"
            type="file"
            accept=".json,.har"
            disabled={loading}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              event.target.value = '';
              if (!file) return;
              setLoading(true);
              try {
                if (file.size > 400 * 1024 * 1024) throw new Error('Session exceeds 400 MiB');
                setSession(
                  await post<Difference[]>('session/compare', token, JSON.parse(await file.text())),
                );
              } catch (error) {
                notify(String(error), true);
              } finally {
                setLoading(false);
              }
            }}
          />
        </label>
        {session && (
          <section>
            <h3>Session comparison</h3>
            <p id="session-comparison-summary">
              {['added', 'removed', 'changed', 'equal', 'unknown']
                .map(
                  (result) =>
                    `${session.filter((item) => item.result === result).length} ${result}`,
                )
                .join(' · ')}
            </p>
            <div className="max-h-60 overflow-auto">
              <table className="headers-table">
                <tbody>
                  {session
                    .filter((item) => item.result !== 'equal')
                    .map((item, index) => (
                      <tr key={index}>
                        <td>{item.result}</td>
                        <td>
                          {item.method} {item.url}
                          <br />
                          {item.fields.join(', ')}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
        {pair && (
          <>
            <p id="exchange-comparison-result">
              {pair.difference.result}:{' '}
              {pair.difference.fields.join(', ') || 'Captured fields match'}
            </p>
            <NativeSelect
              aria-label="Comparison message"
              value={phase}
              onChange={(event) => setPhase(event.target.value)}
            >
              <option value="request">Request</option>
              <option value="response">Response</option>
            </NativeSelect>
            <div className="grid min-w-0 grid-cols-1 gap-5 md:grid-cols-2">
              {[pair.left, pair.right].map((flow, index) => {
                const message = phase === 'request' ? flow.request : flow.response;
                return (
                  <section className="min-w-0" key={index}>
                    <h3>
                      #{flow.id} {flow.method}
                    </h3>
                    <p>{flow.upstream_url}</p>
                    {message ? (
                      <>
                        <HeaderTable headers={message.headers} />
                        <BodyView
                          message={message}
                          id={flow.id}
                          direction={`comparison-${phase}`}
                        />
                      </>
                    ) : (
                      <p>No response captured.</p>
                    )}
                  </section>
                );
              })}
            </div>
          </>
        )}
      </div>
      <div className="dialog-footer">
        <Button type="button" variant="outline" onClick={close}>
          Done
        </Button>
      </div>
    </Modal>
  );
}
