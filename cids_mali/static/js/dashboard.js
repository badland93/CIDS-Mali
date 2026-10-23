document.addEventListener('DOMContentLoaded', async () => {
  const dashboard = document.querySelector('.dashboard-main');
  const datasetUrl = dashboard?.dataset.statsUrl;
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isDark = document.body.getAttribute('data-theme') === 'dark';
  const chartText = isDark ? '#CBD5E1' : '#475569';
  const chartGrid = isDark ? 'rgba(203, 213, 225, 0.12)' : 'rgba(71, 85, 105, 0.12)';
  const chartInstances = [];

  document.addEventListener('cids-theme-change', (event) => {
    const dark = event.detail.theme === 'dark';
    const text = dark ? '#CBD5E1' : '#475569';
    const grid = dark ? 'rgba(203, 213, 225, 0.12)' : 'rgba(71, 85, 105, 0.12)';
    chartInstances.forEach((chart) => {
      chart.options.color = text;
      if (chart.options.plugins?.legend?.labels) chart.options.plugins.legend.labels.color = text;
      Object.values(chart.options.scales || {}).forEach((scale) => {
        scale.ticks.color = text;
        scale.grid.color = grid;
      });
      chart.update('none');
    });
  });

  const renderKpis = (payload) => {
    const kpiGrid = document.getElementById('kpi-grid');
    if (!kpiGrid || !payload?.kpis) return;
    const items = [
      { icon: 'users', label: 'Candidats', value: payload.kpis.total_candidates },
      { icon: 'id-card', label: 'Cartes émises', value: payload.kpis.total_issued },
      { icon: 'badge-check', label: 'Cartes actives', value: payload.kpis.active_cards },
      { icon: 'badge-alert', label: 'Cartes expirées', value: payload.kpis.expired },
      { icon: 'scan-line', label: 'Vérifications', value: payload.kpis.total_verifications },
      { icon: 'school', label: 'Établissements', value: payload.kpis.registered_institutions },
    ];

    kpiGrid.innerHTML = items.map((item) => `
      <article class="kpi-card panel">
        <span class="kpi-icon" aria-hidden="true"><i data-lucide="${item.icon}"></i></span>
        <span class="kpi-label">${item.label}</span>
        <strong>${Number(item.value).toLocaleString('fr-FR')}</strong>
      </article>
    `).join('');
    window.lucide?.createIcons();
  };

  const renderActivity = (payload) => {
    const list = document.getElementById('activity-list');
    if (!list || !payload?.recent_activity) return;
    const fragment = document.createDocumentFragment();
    payload.recent_activity.forEach((item) => {
      const row = document.createElement('li');
      const dot = document.createElement('span');
      dot.className = `dot dot--${['issue', 'revoke', 'verify'].includes(item.type) ? item.type : 'issue'}`;
      const details = document.createElement('div');
      const title = document.createElement('strong');
      const meta = document.createElement('small');
      title.textContent = item.title;
      meta.textContent = `${item.time} · Opérateur ${item.operator}`;
      details.append(title, meta);
      row.append(dot, details);
      fragment.append(row);
    });
    list.replaceChildren(fragment);
  };

  const renderAlerts = (payload) => {
    const list = document.getElementById('alert-list');
    if (!list || !payload?.alerts) return;
    const fragment = document.createDocumentFragment();
    payload.alerts.forEach((alert) => {
      const row = document.createElement('li');
      const level = ['warning', 'info', 'danger'].includes(alert.level) ? alert.level : 'info';
      row.className = `alert-item ${level}`;
      row.textContent = alert.message;
      fragment.append(row);
    });
    list.replaceChildren(fragment);
  };

  try {
    if (!datasetUrl) throw new Error('Dashboard endpoint unavailable');
    const response = await fetch(datasetUrl, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('Dataset unavailable');
    const payload = await response.json();

    renderKpis(payload);
    renderActivity(payload);
    renderAlerts(payload);

    const chartConfigs = [
      {
        id: 'issued-by-month',
        type: 'line',
        data: payload.issued_per_month,
        options: { fill: true, tension: 0.35 }
      },
      {
        id: 'status-donut',
        type: 'doughnut',
        data: payload.status_breakdown,
        options: { cutout: '60%' }
      },
      {
        id: 'by-class',
        type: 'bar',
        data: payload.by_class,
        options: { indexAxis: 'y' }
      },
      {
        id: 'verification-stack',
        type: 'bar',
        data: payload.verifications_per_day,
        options: { stacked: true }
      },
      {
        id: 'rejection-bars',
        type: 'bar',
        data: payload.rejection_reasons,
        options: { indexAxis: 'y' }
      }
    ];

    chartConfigs.forEach((config) => {
      const canvas = document.getElementById(config.id);
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      const chart = new Chart(ctx, {
        type: config.type,
        data: {
          labels: config.data.labels,
          datasets: config.data.datasets || [{
            label: 'Valeur',
            data: config.data.values,
            backgroundColor: ['#4C8C6A', '#E9C46A', '#C8553D', '#5B8DB8'],
            borderRadius: 8,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: prefersReducedMotion ? false : { duration: 800 },
          color: chartText,
          plugins: { legend: { display: true, labels: { color: chartText } } },
          scales: {
            x: { ticks: { color: chartText }, grid: { color: chartGrid } },
            y: { ticks: { color: chartText }, grid: { color: chartGrid } },
          },
          ...config.options
        }
      });
      chartInstances.push(chart);
    });

    const gauge = document.querySelector('.gauge-ring');
    if (gauge) {
      const rate = Number(gauge.dataset.rate || 0);
      gauge.style.setProperty('--gauge-angle', `${rate * 3.6}deg`);
      gauge.style.background = `conic-gradient(var(--primary) 0 ${rate}%, var(--border) ${rate}% 100%)`;
      const value = gauge.querySelector('.gauge-ring__inner');
      if (value) value.textContent = `${rate}%`;
    }
  } catch (error) {
    console.warn('Dashboard data unavailable.');
  }
});
