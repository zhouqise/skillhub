// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const api = vi.hoisted(() => ({ get: vi.fn(), save: vi.fn(), test: vi.fn() }))
vi.mock('@/api/client', () => ({ ldapSettingsApi: api, ApiError: class extends Error {} }))
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
import { LdapSettingsPage } from './ldap'
const settings = { version: 1, passwordConfigured: true, encryptionConfigured: true, identityLocked: true,
  configuration: { enabled: false, directoryId: 'corp', baseDn: 'dc=example,dc=com', userSearchBase: 'ou=people',
    userFilter: '(uid={0})', displayNameAttribute: 'cn', emailAttribute: '', tlsMode: 'STARTTLS' } }
async function mount(filter = '(uid={0})') {
  api.get.mockResolvedValue({ ...settings, configuration: { ...settings.configuration, userFilter: filter } })
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><LdapSettingsPage /></QueryClientProvider>)
  await screen.findByLabelText('ldapSettings.userOu')
}
beforeEach(() => { vi.clearAllMocks(); api.test.mockResolvedValue(undefined) })
afterEach(cleanup)
describe('simplified LDAP configuration', () => {
  it('combines the existing OU and submits changed mappings without losing the identity or password semantics', async () => {
    await mount()
    expect((screen.getByLabelText('ldapSettings.userOu') as HTMLInputElement).value).toBe('ou=people,dc=example,dc=com')
    expect(document.querySelector('details')?.open).toBe(false)
    fireEvent.change(screen.getByLabelText('ldapSettings.userOu'), { target: { value: 'ou=staff,dc=example,dc=com' } })
    fireEvent.change(screen.getByLabelText('ldapSettings.loginAttribute'), { target: { value: 'sAMAccountName' } })
    fireEvent.change(screen.getByLabelText('ldapSettings.displayNameAttribute'), { target: { value: 'displayName' } })
    fireEvent.change(screen.getByLabelText('ldapSettings.emailAttribute'), { target: { value: 'mail' } })
    fireEvent.click(screen.getByText('ldapSettings.test'))
    await waitFor(() => expect(api.test).toHaveBeenCalled())
    expect(api.test.mock.calls[0][0]).toMatchObject({ version: 1, configuration: {
      directoryId: 'corp', bindPassword: '', baseDn: 'ou=staff,dc=example,dc=com', userSearchBase: '',
      userFilter: '(sAMAccountName={0})', displayNameAttribute: 'displayName', emailAttribute: 'mail', tlsMode: 'STARTTLS',
    } })
    expect(api.save).not.toHaveBeenCalled()
  })
  it.each(['(&(objectClass=person)(uid={0}))', '(cn~={0})', '(uid:dn:={0})'])('preserves custom filter %s and split search paths when only changing the email mapping', async (filter) => {
    await mount(filter)
    expect((screen.getByLabelText('ldapSettings.loginAttribute') as HTMLInputElement).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('ldapSettings.emailAttribute'), { target: { value: 'mail' } })
    fireEvent.click(screen.getByText('ldapSettings.test'))
    await waitFor(() => expect(api.test).toHaveBeenCalled())
    expect(api.test.mock.calls[0][0].configuration).toMatchObject({ userFilter: filter, baseDn: 'dc=example,dc=com', userSearchBase: 'ou=people' })
  })
})
