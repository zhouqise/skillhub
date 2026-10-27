import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ApiError, ldapSettingsApi, type LdapConfiguration, type LdapSettings } from '@/api/client'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

const queryKey = ['system-config', 'ldap']
const simpleFilter = /^\(([a-zA-Z][a-zA-Z0-9-]*)=\{0\}\)$/
const timeoutFields = ['connectTimeoutMs', 'readTimeoutMs', 'searchTimeLimitMs'] as const

export function LdapSettingsPage() {
  const { t } = useTranslation()
  const [saved, setSaved] = useState(false)
  const query = useQuery({ queryKey, queryFn: ldapSettingsApi.get })
  if (query.isPending) return <p>{t('ldapSettings.loading')}</p>
  if (query.isError) return <div role="alert"><p>{query.error.message}</p><Button onClick={() => void query.refetch()}>{t('ldapSettings.retry')}</Button></div>
  return <div className="space-y-3">{saved && <p role="status">{t('ldapSettings.saved')}</p>}<LdapSettingsForm key={query.data.version} settings={query.data} onSaved={() => setSaved(true)} onChange={() => setSaved(false)} /></div>
}

function LdapSettingsForm({ settings, onSaved, onChange }: { settings: LdapSettings; onSaved: () => void; onChange: () => void }) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const [draft, setDraft] = useState<LdapConfiguration>({ ...settings.configuration, directoryId: settings.configuration.directoryId || 'company', bindPassword: '' })
  const [customFilter, setCustomFilter] = useState(!simpleFilter.test(settings.configuration.userFilter ?? '(uid={0})'))
  const loginAttribute = /^\(([^()=]*)=\{0\}\)$/.exec(draft.userFilter ?? '(uid={0})')?.[1]
  const userOu = [draft.userSearchBase, draft.baseDn].filter(Boolean).join(',')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const save = useMutation({ mutationFn: ldapSettingsApi.save, onSuccess: async (value) => {
    onSaved()
    client.setQueryData(queryKey, value)
    await client.invalidateQueries({ queryKey: ['auth'] })
  } })
  const test = useMutation({ mutationFn: ldapSettingsApi.test })
  const busy = save.isPending || test.isPending
  function change<K extends keyof LdapConfiguration>(key: K, value: LdapConfiguration[K]) {
    onChange()
    setDraft(current => ({ ...current, [key]: value }))
    setMessage(''); setError('')
  }
  function textField(field: 'url' | 'bindDn' | 'directoryId' | 'userFilter' | 'displayNameAttribute' | 'emailAttribute', placeholder?: string) {
    return <div className="space-y-2"><Label htmlFor={field}>{t(`ldapSettings.${field}`)}</Label>
      <Input id={field} value={draft[field] ?? ''} disabled={field === 'directoryId' && settings.identityLocked}
        onChange={e => { change(field, e.target.value); if (field === 'userFilter') setCustomFilter(!simpleFilter.test(e.target.value)) }} maxLength={2048} autoComplete="off" placeholder={placeholder} /></div>
  }
  async function run(kind: 'save' | 'test') {
    setMessage(''); setError('')
    try {
      await (kind === 'save' ? save : test).mutateAsync({ version: settings.version, configuration: draft })
      if (kind === 'save') setDraft(current => ({ ...current, bindPassword: '' }))
      setMessage(t(kind === 'save' ? 'ldapSettings.saved' : 'ldapSettings.testPassed'))
    } catch (cause) { setError(cause instanceof ApiError && cause.status === 409 ? t('systemConfig.changedElsewhere') : cause instanceof Error ? cause.message : t('ldapSettings.failed')) }
  }
  return <Card className="max-w-3xl">
    <CardHeader><CardTitle>{t('ldapSettings.title')}</CardTitle><p className="text-sm text-muted-foreground">{t('ldapSettings.description')}</p></CardHeader>
    <CardContent><form className="space-y-5" onSubmit={event => { event.preventDefault(); void run('save') }}>
      {!settings.encryptionConfigured && <p role="alert" className="text-destructive">{t('ldapSettings.keyMissing')}</p>}
      {settings.identityLocked && <p className="text-sm text-muted-foreground">{t('ldapSettings.identityLocked')}</p>}
      <fieldset disabled={busy} className="space-y-5">
        <Label className="flex items-center gap-2"><input type="checkbox" checked={draft.enabled ?? false} onChange={e => change('enabled', e.target.checked)} />{t('ldapSettings.enabled')}</Label>
        <section className="space-y-4" aria-labelledby="connection-title">
          <h2 id="connection-title" className="font-semibold">{t('ldapSettings.connection')}</h2>
          {textField('url', 'ldap://ldap.example.com:389')}
          {textField('bindDn', 'cn=reader,ou=service_accounts,dc=example,dc=com')}
          <div className="space-y-2"><Label htmlFor="bindPassword">{t('ldapSettings.bindPassword')}</Label>
            <Input id="bindPassword" type="password" autoComplete="new-password" maxLength={4096} value={draft.bindPassword ?? ''} onChange={e => change('bindPassword', e.target.value)} />
            <p className="text-xs text-muted-foreground">{t(settings.passwordConfigured ? 'ldapSettings.passwordSaved' : 'ldapSettings.passwordEmpty')}</p></div>
          <div className="space-y-2"><Label htmlFor="tlsMode">{t('ldapSettings.tlsMode')}</Label>
            <select id="tlsMode" className="w-full rounded-md border bg-background p-2" value={draft.tlsMode ?? 'LDAPS'} onChange={e => change('tlsMode', e.target.value)}>
              <option value="LDAPS">LDAPS</option><option value="STARTTLS">STARTTLS</option><option value="PLAIN">{t('ldapSettings.plain')}</option>
            </select></div>
        </section>
        <section className="space-y-4 border-t pt-5" aria-labelledby="search-title">
          <h2 id="search-title" className="font-semibold">{t('ldapSettings.search')}</h2>
          <div className="space-y-2"><Label htmlFor="userOu">{t('ldapSettings.userOu')}</Label>
            <Input id="userOu" value={userOu} maxLength={2048} autoComplete="off" placeholder="ou=people,dc=example,dc=com"
              onChange={e => { onChange(); setDraft(current => ({ ...current, baseDn: e.target.value, userSearchBase: '' })); setMessage(''); setError('') }} />
            <p className="text-xs text-muted-foreground">{t('ldapSettings.userOuHint')}</p></div>
        </section>
        <section className="space-y-4 border-t pt-5" aria-labelledby="mapping-title">
          <h2 id="mapping-title" className="font-semibold">{t('ldapSettings.mapping')}</h2>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2"><Label htmlFor="loginAttribute">{t('ldapSettings.loginAttribute')}</Label>
              <Input id="loginAttribute" pattern="[a-zA-Z][a-zA-Z0-9-]*" maxLength={128} value={loginAttribute ?? ''} disabled={customFilter} autoComplete="off" placeholder="uid"
                onChange={e => change('userFilter', `(${e.target.value}={0})`)} /></div>
            {textField('displayNameAttribute', 'displayName')}
            {textField('emailAttribute', 'mail')}
          </div>
          <p className="text-xs text-muted-foreground">{t('ldapSettings.mappingHint')}</p>
          {customFilter && <p className="text-sm">{t('ldapSettings.customFilterHint')}</p>}
        </section>
        <details className="border-t pt-5">
          <summary className="cursor-pointer font-medium">{t('ldapSettings.advanced')}</summary>
          <div className="mt-4 grid gap-5 md:grid-cols-2">
          {textField('directoryId')}
          {textField('userFilter', '(uid={0})')}
          <div className="space-y-2"><Label htmlFor="subjectAttribute">{t('ldapSettings.subjectAttribute')}</Label>
            <select id="subjectAttribute" className="w-full rounded-md border bg-background p-2" value={draft.subjectAttribute ?? 'entryUUID'} disabled={settings.identityLocked} onChange={e => change('subjectAttribute', e.target.value)}>
              <option value="entryUUID">entryUUID (OpenLDAP)</option><option value="objectGUID">objectGUID (Active Directory)</option>
            </select></div>
          {timeoutFields.map(field => <div key={field} className="space-y-2"><Label htmlFor={field}>{t(`ldapSettings.${field}`)}</Label>
            <Input id={field} type="number" min={1} max={30000} required value={draft[field] ?? 5000} onChange={e => change(field, Number(e.target.value))} /></div>)}
          </div>
        </details>
      </fieldset>
      {error && <div role="alert"><p className="text-destructive">{error}</p><Button type="button" variant="outline" disabled={busy} onClick={() => void client.invalidateQueries({ queryKey })}>{t('ldapSettings.retry')}</Button></div>}
      {message && <p role="status">{message}</p>}
      <div className="flex gap-3"><Button type="button" variant="outline" disabled={busy} onClick={() => void run('test')}>{t(test.isPending ? 'ldapSettings.testing' : 'ldapSettings.test')}</Button>
        <Button type="submit" disabled={busy || !settings.encryptionConfigured}>{t(save.isPending ? 'ldapSettings.saving' : 'ldapSettings.save')}</Button></div>
      <p className="text-xs text-muted-foreground">{t('ldapSettings.testHint')}</p>
    </form></CardContent>
  </Card>
}
