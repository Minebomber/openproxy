export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
export async function fetchApi(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`/api/${path}`, { ...options, headers });
  if (!response.ok) throw new ApiError(response.status, await response.text());
  return response;
}
export async function request<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetchApi(path, token, options);
  return response.status === 204 ? (undefined as T) : response.json();
}
export function post<T>(path: string, token: string, value: unknown): Promise<T> {
  return request<T>(path, token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
  });
}
