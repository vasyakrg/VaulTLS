<template>
  <div class="audit-tab">
    <div class="audit-header">
      <h2>{{ $t('audit.title') }}</h2>
      <div class="audit-purge">
        <select v-model="purgeChoice">
          <option value="30">{{ $t('audit.olderThan', { days: 30 }) }}</option>
          <option value="90">{{ $t('audit.olderThan', { days: 90 }) }}</option>
          <option value="180">{{ $t('audit.olderThan', { days: 180 }) }}</option>
          <option value="all">{{ $t('audit.all') }}</option>
        </select>
        <button class="btn-danger" @click="onPurge">{{ $t('audit.purge') }}</button>
      </div>
    </div>

    <div class="audit-filters">
      <select v-model="filters.action" @change="reload">
        <option value="">{{ $t('audit.anyAction') }}</option>
        <option v-for="a in ACTIONS" :key="a" :value="a">{{ a }}</option>
      </select>
      <select v-model="filters.result" @change="reload">
        <option value="">{{ $t('audit.anyResult') }}</option>
        <option value="success">success</option>
        <option value="failure">failure</option>
      </select>
      <input type="date" v-model="fromDate" @change="reload" />
      <input type="date" v-model="toDate" @change="reload" />
    </div>

    <table class="audit-table">
      <thead>
        <tr>
          <th>{{ $t('audit.time') }}</th>
          <th>{{ $t('audit.actor') }}</th>
          <th>{{ $t('audit.action') }}</th>
          <th>{{ $t('audit.target') }}</th>
          <th>{{ $t('audit.result') }}</th>
          <th>IP</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.id">
          <td>{{ new Date(r.ts * 1000).toLocaleString() }}</td>
          <td>{{ r.actor_label }} <small>({{ r.actor_type }})</small></td>
          <td>{{ r.action }}<small v-if="r.detail"> · {{ r.detail }}</small></td>
          <td>{{ r.target_label || r.target_type || '—' }}<small v-if="r.target_id"> #{{ r.target_id }}</small></td>
          <td :class="r.result === 'failure' ? 'res-fail' : 'res-ok'">{{ r.result }}</td>
          <td>{{ r.ip || '—' }}</td>
        </tr>
        <tr v-if="rows.length === 0"><td colspan="6" class="empty">{{ $t('audit.empty') }}</td></tr>
      </tbody>
    </table>

    <div class="audit-pager">
      <button :disabled="offset === 0" @click="prev">‹</button>
      <span>{{ offset + 1 }}–{{ Math.min(offset + limit, total) }} / {{ total }}</span>
      <button :disabled="offset + limit >= total" @click="next">›</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { fetchAudit, purgeAudit } from '@/api/audit';
import type { AuditLogRow } from '@/types/Audit';

const { t } = useI18n();

const ACTIONS = [
  'login','logout','download_certificate','fetch_certificate_password',
  'create_ca','import_ca','delete_ca','revoke_certificate','delete_certificate',
  'create_user','update_user','delete_user','create_group','update_group','delete_group',
  'create_service_account','revoke_service_account','delete_service_account','update_settings',
];

const rows = ref<AuditLogRow[]>([]);
const total = ref(0);
const limit = ref(50);
const offset = ref(0);
const filters = reactive({ action: '', result: '' });
const fromDate = ref('');
const toDate = ref('');
const purgeChoice = ref('90');

const toTs = (d: string): number | undefined =>
  d ? Math.floor(new Date(d).getTime() / 1000) : undefined;

async function reload() {
  offset.value = 0;
  await load();
}
async function load() {
  const page = await fetchAudit({
    action: filters.action || undefined,
    result: filters.result || undefined,
    from: toTs(fromDate.value),
    to: toTs(toDate.value),
    limit: limit.value,
    offset: offset.value,
  });
  rows.value = page.rows;
  total.value = page.total;
}
function prev() { offset.value = Math.max(0, offset.value - limit.value); load(); }
function next() { offset.value += limit.value; load(); }

async function onPurge() {
  let before: number;
  if (purgeChoice.value === 'all') {
    before = Math.floor(Date.now() / 1000) + 1;
  } else {
    before = Math.floor(Date.now() / 1000) - Number(purgeChoice.value) * 86400;
  }
  if (!confirm(t('audit.confirmPurge'))) return;
  await purgeAudit(before);
  await reload();
}

onMounted(load);
</script>

<style scoped>
.audit-tab { padding: 16px; }
.audit-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.audit-purge { display: flex; gap: 8px; }
.audit-filters { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.audit-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.audit-table th, .audit-table td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--vt-border); }
.audit-table small { color: var(--vt-muted); }
.res-fail { color: #e5484d; }
.res-ok { color: var(--vt-muted); }
.empty { text-align: center; color: var(--vt-muted); padding: 24px; }
.audit-pager { display: flex; gap: 12px; align-items: center; justify-content: center; margin-top: 12px; }
.btn-danger { background: #e5484d; color: #fff; border: none; border-radius: 6px; padding: 6px 12px; cursor: pointer; }
</style>
