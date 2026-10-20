/** @vitest-environment jsdom */
import { act, cleanup, renderHook } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({ localLogin: vi.fn(), directLogin: vi.fn() }))
vi.mock('@/api/client', () => ({
  authApi: api,
  getDirectAuthRuntimeConfig: () => ({ enabled: true, provider: 'legacy' }),
}))
import { usePasswordLogin } from './use-password-login'

function wrapper({ children }: { children: ReactNode }) {
  return createElement(QueryClientProvider, { client: new QueryClient() }, children)
}
afterEach(() => { cleanup(); vi.clearAllMocks() })

describe('explicit password login routing', () => {
  const credentials = { username: 'alice', password: 'secret' }
  it('keeps ordinary login local despite global direct configuration', async () => {
    const { result } = renderHook(() => usePasswordLogin('local'), { wrapper })
    await act(() => result.current.mutateAsync(credentials))
    expect(api.localLogin).toHaveBeenCalledWith(credentials)
    expect(api.directLogin).not.toHaveBeenCalled()
  })
  it('routes LDAP only to the LDAP provider', async () => {
    const { result } = renderHook(() => usePasswordLogin({ provider: 'ldap' }), { wrapper })
    await act(() => result.current.mutateAsync(credentials))
    expect(api.directLogin).toHaveBeenCalledWith('ldap', credentials)
    expect(api.localLogin).not.toHaveBeenCalled()
  })
  it('preserves implicit routing for existing hook callers', async () => {
    const { result } = renderHook(() => usePasswordLogin(), { wrapper })
    await act(() => result.current.mutateAsync(credentials))
    expect(api.directLogin).toHaveBeenCalledWith('legacy', credentials)
  })
})
