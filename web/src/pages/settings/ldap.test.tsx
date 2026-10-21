import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'
const query = vi.hoisted(() => vi.fn())
vi.mock('@tanstack/react-query', () => ({
  useQuery: query,
  useMutation: () => ({ isPending: false, mutateAsync: vi.fn() }),
  useQueryClient: () => ({ setQueryData: vi.fn(), invalidateQueries: vi.fn() }),
}))
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
vi.mock('@/api/client', () => ({ ldapSettingsApi: {}, ApiError: class extends Error {} }))
import { LdapSettingsPage } from './ldap'
beforeEach(() => query.mockReturnValue({ data: {
  version: 0, configuration: { enabled: false, directoryId: 'corp', subjectAttribute: 'entryUUID' },
  passwordConfigured: true, encryptionConfigured: true, identityLocked: true,
} }))
describe('LDAP settings form', () => {
  it('does not populate a stored password and explains preservation and identity locks', () => {
    const html = renderToStaticMarkup(<LdapSettingsPage />)
    expect(html).toContain('ldapSettings.passwordSaved')
    expect(html).toContain('ldapSettings.identityLocked')
    expect(html).toMatch(/id="directoryId"[^>]*disabled=""/)
    expect(html).toMatch(/id="bindPassword"[^>]*value=""/)
    expect(html).toContain('ldapSettings.testHint')
  })
  it('blocks saving when the deployment encryption key is absent', () => {
    query.mockReturnValue({ data: { version: -1, configuration: {}, encryptionConfigured: false } })
    const html = renderToStaticMarkup(<LdapSettingsPage />)
    expect(html).toContain('ldapSettings.keyMissing')
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*disabled=""/)
  })
  it('shows load failure instead of a default writable form', () => {
    query.mockReturnValue({ isError: true, error: new Error('Unavailable') })
    const html = renderToStaticMarkup(<LdapSettingsPage />)
    expect(html).toContain('Unavailable')
    expect(html).not.toContain('id="bindPassword"')
  })
})
