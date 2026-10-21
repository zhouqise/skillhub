import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ApiError, ldapSettingsApi, type LdapConfiguration, type LdapSettings } from '@/api/client'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

const queryKey = ['system-config', 'ldap']
const textFields = ['directoryId', 'url', 'baseDn', 'bindDn', 'userSearchBase', 'userFilter', 'displayNameAttribute'] as const
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
  const [draft, setDraft] = useState<LdapConfiguration>({ ...settings.configuration, bindPassword: '' })
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
        <div className="grid gap-5 md:grid-cols-2">
          {textFields.map(field => <div key={field} className="space-y-2"><Label htmlFor={field}>{t(`ldapSettings.${field}`)}</Label>
            <Input id={field} value={draft[field] ?? ''} disabled={field === 'directoryId' && settings.identityLocked} onChange={e => change(field, e.target.value)} maxLength={2048} autoComplete="off" placeholder={field === 'url' ? 'ldaps://ldap.example.com:636' : undefined} />
          </div>)}
          <div className="space-y-2"><Label htmlFor="tlsMode">{t('ldapSettings.tlsMode')}</Label>
            <select id="tlsMode" className="w-full rounded-md border bg-background p-2" value={draft.tlsMode ?? 'LDAPS'} onChange={e => change('tlsMode', e.target.value)}>
              <option value="LDAPS">LDAPS</option><option value="STARTTLS">STARTTLS</option><option value="PLAIN">{t('ldapSettings.plain')}</option>
            </select></div>
          <div className="space-y-2"><Label htmlFor="subjectAttribute">{t('ldapSettings.subjectAttribute')}</Label>
            <select id="subjectAttribute" className="w-full rounded-md border bg-background p-2" value={draft.subjectAttribute ?? 'entryUUID'} disabled={settings.identityLocked} onChange={e => change('subjectAttribute', e.target.value)}>
              <option value="entryUUID">entryUUID (OpenLDAP)</option><option value="objectGUID">objectGUID (Active Directory)</option>
            </select></div>
          <div className="space-y-2"><Label htmlFor="bindPassword">{t('ldapSettings.bindPassword')}</Label>
            <Input id="bindPassword" type="password" autoComplete="new-password" maxLength={4096} value={draft.bindPassword ?? ''} onChange={e => change('bindPassword', e.target.value)} />
            <p className="text-xs text-muted-foreground">{t(settings.passwordConfigured ? 'ldapSettings.passwordSaved' : 'ldapSettings.passwordEmpty')}</p></div>
          {timeoutFields.map(field => <div key={field} className="space-y-2"><Label htmlFor={field}>{t(`ldapSettings.${field}`)}</Label>
            <Input id={field} type="number" min={1} max={30000} required value={draft[field] ?? 5000} onChange={e => change(field, Number(e.target.value))} /></div>)}
        </div>
      </fieldset>
      {error && <div role="alert"><p className="text-destructive">{error}</p><Button type="button" variant="outline" disabled={busy} onClick={() => void client.invalidateQueries({ queryKey })}>{t('ldapSettings.retry')}</Button></div>}
      {message && <p role="status">{message}</p>}
      <div className="flex gap-3"><Button type="button" variant="outline" disabled={busy} onClick={() => void run('test')}>{t(test.isPending ? 'ldapSettings.testing' : 'ldapSettings.test')}</Button>
        <Button type="submit" disabled={busy || !settings.encryptionConfigured}>{t(save.isPending ? 'ldapSettings.saving' : 'ldapSettings.save')}</Button></div>
      <p className="text-xs text-muted-foreground">{t('ldapSettings.testHint')}</p>
    </form></CardContent>
  </Card>
}
