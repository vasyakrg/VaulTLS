<template>
  <div>
    <header class="vt-head">
      <div>
        <h1>{{ $t('agents.title') }}</h1>
        <p class="vt-sub">{{ $t('agents.subtitle') }}</p>
      </div>
      <div class="vt-actions">
        <Button
          id="AgentsRefreshButton"
          icon="pi pi-refresh"
          v-tooltip.top="$t('agents.refresh')"
          :aria-label="$t('agents.refresh')"
          @click="agentsStore.fetchAgents()"
        />
      </div>
    </header>

    <div v-if="loading" class="vt-status">{{ $t('common.loading') }}</div>
    <div v-if="error" class="vt-error">{{ error }}</div>

    <DataTable
      :value="tableRows"
      dataKey="id"
      class="vt-table"
      paginator
      :rows="rowsPerPage"
      :rowsPerPageOptions="[15, 30]"
    >
      <template #header>
        <div class="vt-table-header">
          <div class="vt-filter-row">
            <div class="p-input-icon-left vt-search-wrap">
              <i class="pi pi-search" />
              <InputText
                id="AgentsSearchInput"
                v-model="search"
                :placeholder="$t('common.search')"
                class="vt-search"
              />
            </div>
            <Select
              id="AgentsStatusFilter"
              v-model="statusFilter"
              :options="statusOptions"
              optionLabel="label"
              optionValue="value"
              :placeholder="$t('agents.colStatus')"
              showClear
              class="vt-type-filter"
            />
          </div>
        </div>
      </template>

      <Column field="hostname" sortable :header="$t('agents.colHostname')">
        <template #body="{ data }">
          <span :id="'AgentHostname-' + data.id" class="vt-mono">{{ data.hostname || data.agent_uuid }}</span>
        </template>
      </Column>
      <Column field="account_name" sortable :header="$t('agents.colAccount')">
        <template #body="{ data }">
          <span>{{ data.account_name }}</span>
          <span class="vt-muted-inline"> ({{ data.owner_login }})</span>
        </template>
      </Column>
      <Column field="version" sortable :header="$t('agents.colVersion')">
        <template #body="{ data }">
          <span class="vt-mono">{{ data.version }}</span>
        </template>
      </Column>
      <Column field="overall" sortable sortField="overall" :header="$t('agents.colStatus')">
        <template #body="{ data }">
          <Tag :id="'AgentStatus-' + data.id" :severity="overallSeverity(data)" :value="overallLabel(data)" />
        </template>
      </Column>
      <Column field="domains.length" :header="$t('agents.colDomains')">
        <template #body="{ data }">
          <span :id="'AgentDomains-' + data.id">
            {{ data.domains.length }}
            <Tag
              v-if="data.error_count > 0"
              class="vt-error-chip"
              severity="danger"
              :value="String(data.error_count)"
            />
          </span>
        </template>
      </Column>
      <Column field="soonest_expiry_ms" sortable :header="$t('agents.colExpiry')">
        <template #body="{ data }">
          <span v-if="data.soonest_expiry_ms">{{ formatDate(data.soonest_expiry_ms) }}</span>
          <span v-else class="vt-muted-inline">—</span>
        </template>
      </Column>
      <Column field="last_seen" sortable :header="$t('agents.colLastSeen')">
        <template #body="{ data }">
          <span :id="'AgentLastSeen-' + data.id" v-tooltip.top="formatDate(data.last_seen)">
            {{ timeAgo(data.last_seen) }}
          </span>
        </template>
      </Column>
      <Column :header="$t('common.actions')" class="vt-row-actions">
        <template #body="{ data }">
          <Button
            :id="'AgentDetailsButton-' + data.id"
            icon="pi pi-eye"
            severity="secondary"
            rounded
            text
            v-tooltip.top="$t('agents.details')"
            :aria-label="$t('agents.details')"
            @click="openDetails(data)"
          />
        </template>
      </Column>
      <template #empty>
        <div class="vt-empty">{{ $t('agents.empty') }}</div>
      </template>
    </DataTable>

    <!-- Per-agent detail: run-level facts + the per-domain snapshot -->
    <BaseModal
      v-model:visible="detailsVisible"
      :title="detailsTitle"
      :submit-label="$t('common.cancel')"
      submit-severity="secondary"
      :width="'720px'"
      @cancel="detailsVisible = false"
      @submit="detailsVisible = false"
    >
      <div v-if="selected" class="vt-detail">
        <dl class="vt-detail-grid">
          <div><dt>{{ $t('agents.colVersion') }}</dt><dd class="vt-mono">{{ selected.version || '—' }}</dd></div>
          <div><dt>{{ $t('agents.colPlatform') }}</dt><dd>{{ selected.os }}/{{ selected.arch }}</dd></div>
          <div><dt>{{ $t('agents.colSchedule') }}</dt><dd class="vt-mono">{{ selected.schedule }}</dd></div>
          <div><dt>{{ $t('agents.colInterval') }}</dt><dd>{{ formatInterval(selected.heartbeat_interval_sec) }}</dd></div>
          <div><dt>{{ $t('agents.colFirstSeen') }}</dt><dd>{{ formatDate(selected.first_seen) }}</dd></div>
          <div><dt>{{ $t('agents.colIp') }}</dt><dd class="vt-mono">{{ selected.ip || '—' }}</dd></div>
          <div><dt>{{ $t('agents.colAgentId') }}</dt><dd class="vt-mono vt-detail-uuid">{{ selected.agent_uuid }}</dd></div>
          <div>
            <dt>{{ $t('agents.colLastError') }}</dt>
            <dd :class="{ 'vt-err-text': selected.last_error }">
              {{ selected.last_error || '—' }}
            </dd>
          </div>
        </dl>

        <DataTable :value="selected.domains" dataKey="destination" class="vt-table vt-detail-table" scrollable>
          <Column field="name" sortable :header="$t('agents.colDomain')">
            <template #body="{ data }">
              <span class="vt-mono">{{ data.name || data.destination }}</span>
            </template>
          </Column>
          <Column field="target" :header="$t('agents.colTarget')">
            <template #body="{ data }">
              <span class="vt-mono">{{ data.destination }}</span>
            </template>
          </Column>
          <Column field="status" sortable :header="$t('agents.colStatus')">
            <template #body="{ data }">
              <Tag :severity="data.status === 'ok' ? 'success' : 'danger'" :value="domainStatusLabel(data)" />
            </template>
          </Column>
          <Column field="serial" :header="$t('agents.colSerial')">
            <template #body="{ data }">
              <span class="vt-mono">{{ data.serial || '—' }}</span>
            </template>
          </Column>
          <Column field="expiry_ms" sortable :header="$t('agents.colExpiry')">
            <template #body="{ data }">
              <span v-if="data.expiry_ms">{{ formatDate(data.expiry_ms) }}</span>
              <span v-else class="vt-muted-inline">—</span>
            </template>
          </Column>
          <Column field="last_check_ms" sortable :header="$t('agents.colLastCheck')">
            <template #body="{ data }">
              <span v-if="data.last_check_ms" v-tooltip.top="formatDate(data.last_check_ms)">
                {{ timeAgo(data.last_check_ms) }}
              </span>
              <span v-else class="vt-muted-inline">—</span>
            </template>
          </Column>
          <template #empty>
            <div class="vt-empty">{{ $t('agents.noDomains') }}</div>
          </template>
        </DataTable>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Tooltip from 'primevue/tooltip'
import { useAgentsStore } from '@/stores/agents'
import type { AgentStatus } from '@/types/Agent'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import BaseModal from '@/components/BaseModal.vue'

const vTooltip = Tooltip
const { t, te } = useI18n()

const agentsStore = useAgentsStore()
const loading = computed(() => agentsStore.loading)
const error = computed(() => agentsStore.error)

const rowsPerPage = ref(15)
const search = ref('')
const statusFilter = ref<string | null>(null)

// offline > error: недоступный агент с ошибками в отчёте всё равно «offline».
const overall = (a: AgentStatus): string => (!a.online ? 'offline' : a.status)

const overallSeverity = (a: AgentStatus): string => {
  switch (overall(a)) {
    case 'ok': return 'success'
    case 'error': return 'danger'
    default: return 'warn'
  }
}

const overallLabel = (a: AgentStatus): string => {
  const key = `agents.${overall(a)}`
  return te(key) ? t(key) : overall(a)
}

const domainStatusLabel = (d: { status: string; stage?: string }): string => {
  if (d.status === 'ok') return t('agents.ok')
  return d.stage ? `${t('agents.error')} · ${d.stage}` : t('agents.error')
}

const statusOptions = [
  { label: t('agents.ok'), value: 'ok' },
  { label: t('agents.error'), value: 'error' },
  { label: t('agents.offline'), value: 'offline' },
]

const tableRows = computed(() => {
  let rows = agentsStore.list
  if (statusFilter.value !== null) {
    rows = rows.filter((a) => overall(a) === statusFilter.value)
  }
  const q = search.value.trim().toLowerCase()
  if (q) {
    rows = rows.filter((a) =>
      a.hostname.toLowerCase().includes(q) ||
      a.account_name.toLowerCase().includes(q) ||
      a.owner_login.toLowerCase().includes(q) ||
      a.version.toLowerCase().includes(q) ||
      String(a.id).includes(q))
  }
  return rows
})

// Детальный диалог
const detailsVisible = ref(false)
const selected = ref<AgentStatus | null>(null)
const detailsTitle = computed(() =>
  selected.value ? selected.value.hostname || selected.value.agent_uuid : '')

const openDetails = (a: AgentStatus) => {
  selected.value = a
  detailsVisible.value = true
}

const formatDate = (ms: number): string => new Date(ms).toLocaleString()

const formatInterval = (sec: number): string => {
  if (sec % 60 !== 0) return `${sec}s`
  const min = sec / 60
  return min % 60 !== 0 ? t('agents.everyMinute', { n: min }) : t('agents.everyHour', { n: min / 60 })
}

// Относительное время «5 минут назад»: dayjs в проекте нет, поэтому локально.
const timeAgo = (ms: number): string => {
  const diffSec = Math.round((Date.now() - ms) / 1000)
  if (diffSec < 60) return t('agents.agoNow')
  if (diffSec < 3600) return t('agents.agoMin', { n: Math.floor(diffSec / 60) })
  if (diffSec < 86400) return t('agents.agoHour', { n: Math.floor(diffSec / 3600) })
  return t('agents.agoDay', { n: Math.floor(diffSec / 86400) })
}

// Polling: агент бьётся каждые N минут, 30 секунд держат last_seen свежим
// без ручного обновления. Первый polling-компонент в проекте.
let pollTimer: number | undefined

onMounted(() => {
  agentsStore.fetchAgents()
  pollTimer = window.setInterval(() => agentsStore.fetchAgents(), 30_000)
})

onUnmounted(() => {
  if (pollTimer !== undefined) window.clearInterval(pollTimer)
})
</script>

<style scoped>
.vt-head {
  display: flex;
  align-items: flex-start;
  margin-bottom: 22px;
}

.vt-head h1 {
  font-size: 22px;
  font-weight: 700;
}

.vt-sub {
  font-size: 13px;
  color: var(--vt-muted);
  margin-top: 3px;
}

.vt-actions {
  margin-left: auto;
  display: flex;
  gap: 10px;
}

.vt-status {
  color: var(--vt-muted);
  font-size: 13px;
  margin-bottom: 12px;
}

.vt-error {
  background: var(--vt-err);
  color: #fff;
  padding: 8px 12px;
  border-radius: 6px;
  margin-bottom: 12px;
  font-size: 13px;
}

.vt-table-header {
  display: flex;
  justify-content: flex-end;
}

.vt-filter-row {
  display: flex;
  gap: 10px;
  align-items: center;
}

.vt-search-wrap {
  position: relative;
}

.vt-search-wrap .pi {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--vt-muted);
}

.vt-search {
  padding-left: 30px;
}

.vt-mono {
  font-family: var(--vt-font-mono, monospace);
  font-size: 12px;
}

.vt-muted-inline {
  color: var(--vt-muted);
  font-size: 12px;
}

.vt-error-chip {
  margin-left: 6px;
}

.vt-empty {
  text-align: center;
  color: var(--vt-muted);
  padding: 18px 0;
}

.vt-detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px 18px;
  margin: 0 0 16px;
}

.vt-detail-grid dt {
  font-size: 12px;
  color: var(--vt-muted);
}

.vt-detail-grid dd {
  margin: 2px 0 0;
  font-size: 13px;
  word-break: break-all;
}

.vt-detail-uuid {
  font-size: 11px;
}

.vt-err-text {
  color: var(--vt-err);
}

.vt-detail-table {
  margin-top: 4px;
}
</style>
