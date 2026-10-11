import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { NativeSelect } from './components/ui/native-select';
import { Textarea } from './components/ui/textarea';
import type { Action, Headers, Rule } from './types';

const defaults: Record<Action['type'], Action> = {
  set_request_header: { type: 'set_request_header', name: 'X-Debug', value: 'OpenProxy' },
  set_response_header: { type: 'set_response_header', name: 'X-Debug', value: 'OpenProxy' },
  remove_request_header: { type: 'remove_request_header', name: 'X-Debug' },
  remove_response_header: { type: 'remove_response_header', name: 'X-Debug' },
  replace_url: { type: 'replace_url', find: 'original', replace: 'replacement', regex: false },
  replace_request_body: {
    type: 'replace_request_body',
    find: 'original',
    replace: 'replacement',
    regex: false,
  },
  replace_response_body: {
    type: 'replace_response_body',
    find: 'original',
    replace: 'replacement',
    regex: false,
  },
  set_query: { type: 'set_query', name: 'debug', value: 'true' },
  map_remote: {
    type: 'map_remote',
    from: 'https://api.example.com/',
    to: 'http://127.0.0.1:3000/',
  },
  map_local: { type: 'map_local', path: './fixtures/response.json', url_prefix: '' },
  mock: {
    type: 'mock',
    status: 200,
    headers: [['Content-Type', 'application/json']],
    body: '{"debug":true}',
  },
  block: { type: 'block', message: 'Blocked by a debugging rule' },
  set_status: { type: 'set_status', status: 200 },
  latency: { type: 'latency', ms: 400 },
  throttle: { type: 'throttle', upload: 64000, download: 96000 },
  failure: { type: 'failure', percent: 100 },
  drop: { type: 'drop', upload_after_bytes: null, download_after_bytes: 1024 },
  no_cache: { type: 'no_cache' },
  mirror: { type: 'mirror', directory: './data/mirrors', max_bytes: 268435456 },
  block_cookies: { type: 'block_cookies' },
  offline: { type: 'offline' },
  breakpoint: { type: 'breakpoint', phase: 'request', timeout_ms: 120000 },
};
const title = (value: string) => value.replaceAll('_', ' ');

function Fields({ action, change }: { action: Action; change: (action: Action) => void }) {
  const fields = { ...defaults[action.type], ...action };
  const set = (name: string, value: unknown) => change({ ...fields, [name]: value } as Action);
  return (
    <div className="grid grid-cols-1 gap-x-3 sm:grid-cols-2">
      {Object.entries(fields)
        .filter(([key]) => key !== 'type')
        .map(([key, value]) => {
          if (action.type === 'drop')
            return (
              <label key={key}>
                {title(key)}
                <Input
                  type="number"
                  min={0}
                  max={Number.MAX_SAFE_INTEGER}
                  value={String(value ?? '')}
                  onChange={(event) =>
                    set(key, event.target.value === '' ? null : Number(event.target.value))
                  }
                />
                <small>Empty = disabled; 0 = drop before any bytes.</small>
              </label>
            );
          if (typeof value === 'boolean')
            return (
              <label key={key} className="flex-row! items-center">
                <input
                  type="checkbox"
                  checked={value}
                  onChange={(event) => set(key, event.target.checked)}
                />
                {title(key)}
              </label>
            );
          if (key === 'headers')
            return (
              <div key={key} className="col-span-full">
                <div className="section-heading mt-3">Headers</div>
                {(value as Headers).map(([name, content], index) => (
                  <div className="my-2 flex gap-2" key={index}>
                    <Input
                      aria-label={`Header ${index + 1} name`}
                      value={name}
                      onChange={(event) =>
                        set(
                          key,
                          (value as Headers).map((header, i) =>
                            i === index ? [event.target.value, header[1]] : header,
                          ),
                        )
                      }
                    />
                    <Input
                      aria-label={`Header ${index + 1} value`}
                      value={content}
                      onChange={(event) =>
                        set(
                          key,
                          (value as Headers).map((header, i) =>
                            i === index ? [header[0], event.target.value] : header,
                          ),
                        )
                      }
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      aria-label={`Remove header ${index + 1}`}
                      onClick={() =>
                        set(
                          key,
                          (value as Headers).filter((_, i) => i !== index),
                        )
                      }
                    >
                      ×
                    </Button>
                  </div>
                ))}
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  onClick={() => set(key, [...(value as Headers), ['', '']])}
                >
                  Add header
                </Button>
              </div>
            );
          if (key === 'value' && action.type === 'set_query')
            return (
              <div key={key}>
                <label>
                  Value
                  <Input
                    disabled={value === null}
                    value={String(value ?? '')}
                    onChange={(event) => set(key, event.target.value)}
                  />
                </label>
                <label className="flex-row! items-center">
                  <input
                    type="checkbox"
                    checked={value === null}
                    onChange={(event) => set(key, event.target.checked ? null : '')}
                  />
                  Remove parameter
                </label>
              </div>
            );
          return (
            <label key={key} className={key === 'body' ? 'col-span-full' : ''}>
              {title(key)}
              {key === 'body' ||
              (action.type.includes('body') && ['find', 'replace'].includes(key)) ? (
                <Textarea
                  rows={3}
                  value={String(value)}
                  onChange={(event) => set(key, event.target.value)}
                />
              ) : (
                <Input
                  type={typeof value === 'number' ? 'number' : 'text'}
                  min={typeof value === 'number' ? 0 : undefined}
                  value={String(value ?? '')}
                  onChange={(event) =>
                    set(
                      key,
                      typeof value === 'number' ? Number(event.target.value) : event.target.value,
                    )
                  }
                />
              )}
            </label>
          );
        })}
    </div>
  );
}

export function RulesEditor({ rules, change }: { rules: Rule[]; change: (rules: Rule[]) => void }) {
  const update = (index: number, next: Rule) =>
    change(rules.map((rule, i) => (i === index ? next : rule)));
  function move(index: number, offset: number) {
    const next = [...rules],
      target = index + offset;
    [next[index], next[target]] = [next[target], next[index]];
    change(next);
  }
  function moveAction(ruleIndex: number, index: number, offset: number) {
    const rule = rules[ruleIndex],
      actions = [...rule.actions],
      target = index + offset;
    [actions[index], actions[target]] = [actions[target], actions[index]];
    update(ruleIndex, { ...rule, actions });
  }
  return (
    <div className="space-y-4">
      {rules.map((rule, index) => (
        <section className="rounded-lg border p-3" key={index} data-rule-index={index}>
          <div className="flex flex-wrap items-center gap-2">
            <label className="my-0! flex-row! items-center">
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(event) => update(index, { ...rule, enabled: event.target.checked })}
              />
              Enabled
            </label>
            <span className="ml-auto text-xs text-muted-foreground">Rule {index + 1}</span>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              disabled={index === 0}
              aria-label={`Move rule ${index + 1} up`}
              onClick={() => move(index, -1)}
            >
              ↑
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              disabled={index === rules.length - 1}
              aria-label={`Move rule ${index + 1} down`}
              onClick={() => move(index, 1)}
            >
              ↓
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              className="text-destructive"
              onClick={() => change(rules.filter((_, i) => i !== index))}
            >
              Remove rule
            </Button>
          </div>
          <label>
            Name
            <Input
              data-field="name"
              value={rule.name}
              maxLength={200}
              onChange={(event) => update(index, { ...rule, name: event.target.value })}
            />
          </label>
          <div className="form-grid">
            <label>
              URL pattern
              <Input
                data-field="url"
                value={rule.url}
                required
                maxLength={4096}
                onChange={(event) => update(index, { ...rule, url: event.target.value })}
              />
            </label>
            <label>
              Method
              <Input
                data-field="method"
                value={rule.method ?? ''}
                placeholder="Any method"
                onChange={(event) => update(index, { ...rule, method: event.target.value || null })}
              />
            </label>
          </div>
          {rule.actions.map((action, actionIndex) => (
            <div className="mt-3 rounded-md border bg-muted/20 p-3" key={actionIndex}>
              <div className="flex items-center justify-between gap-2">
                <NativeSelect
                  aria-label={`Rule ${index + 1} action ${actionIndex + 1}`}
                  value={action.type}
                  onChange={(event) =>
                    update(index, {
                      ...rule,
                      actions: rule.actions.map((item, i) =>
                        i === actionIndex
                          ? structuredClone(defaults[event.target.value as Action['type']])
                          : item,
                      ),
                    })
                  }
                >
                  {Object.keys(defaults).map((type) => (
                    <option key={type} value={type}>
                      {title(type)}
                    </option>
                  ))}
                </NativeSelect>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  aria-label={`Remove action ${actionIndex + 1}`}
                  onClick={() =>
                    update(index, {
                      ...rule,
                      actions: rule.actions.filter((_, i) => i !== actionIndex),
                    })
                  }
                >
                  ×
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  disabled={actionIndex === 0}
                  aria-label={`Move action ${actionIndex + 1} up`}
                  onClick={() => moveAction(index, actionIndex, -1)}
                >
                  ↑
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  disabled={actionIndex === rule.actions.length - 1}
                  aria-label={`Move action ${actionIndex + 1} down`}
                  onClick={() => moveAction(index, actionIndex, 1)}
                >
                  ↓
                </Button>
              </div>
              <Fields
                action={action}
                change={(action) =>
                  update(index, {
                    ...rule,
                    actions: rule.actions.map((item, i) => (i === actionIndex ? action : item)),
                  })
                }
              />
            </div>
          ))}
          <Button
            className="mt-3"
            type="button"
            variant="outline"
            size="sm"
            disabled={rule.actions.length >= 32}
            onClick={() =>
              update(index, {
                ...rule,
                actions: [...rule.actions, structuredClone(defaults.set_request_header)],
              })
            }
          >
            Add action
          </Button>
        </section>
      ))}
      {!rules.length && <p>No rules. Add a rule to edit, pause, map, or simulate traffic.</p>}
      <Button
        id="add-rule"
        type="button"
        variant="outline"
        size="sm"
        disabled={rules.length >= 256}
        onClick={() =>
          change([
            ...rules,
            {
              name: 'New rule',
              enabled: true,
              url: '*',
              method: null,
              actions: [structuredClone(defaults.set_request_header)],
            },
          ])
        }
      >
        Add rule
      </Button>
    </div>
  );
}
