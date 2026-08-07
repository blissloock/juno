/* ============================================================
   Juno — lógica del panel de monitoreo y análisis de red
   Conectado al backend real (Rust/Actix) vía fetch().
   ============================================================ */

(function () {
  'use strict';

  const API_BASE = window.API_BASE || `http://${window.location.hostname}:8080`;
  const TOKEN_KEY = 'juno_token';

  // ---------- Estado de la aplicación ----------
  let dispositivos = [];
  let alertas = [];
  let idsSeleccionados = new Set();
  let filtroEstado = 'todos';
  let textoBusqueda = '';
  let seleccionIndex = null;
  let alertasNoLeidas = 0;
  let ultimoConteoAlertas = 0;
  let intervaloActualizacion = null;

  // ---------- Utilidades ----------
  function claseEstado(estado) {
    if (estado === 'online') return 'online';
    if (estado === 'warning') return 'warning';
    return 'offline';
  }
  function textoEstado(estado) {
    if (estado === 'online') return 'En línea';
    if (estado === 'warning') return 'Advertencia';
    return 'Desconectado';
  }
  function mapSeveridad(s) {
    if (s === 'critica' || s === 'critical') return 'critical';
    if (s === 'advertencia' || s === 'warning') return 'warning';
    return 'info';
  }
  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : str;
    return div.innerHTML;
  }

  // ---------- Referencias DOM ----------
  const pantallaBienvenida = document.getElementById('pantalla-bienvenida');
  const panelPrincipal = document.getElementById('panel-principal');
  const btnEmpezar = document.getElementById('btn-empezar');
  const loginUsuario = document.getElementById('login-usuario');
  const loginPassword = document.getElementById('login-password');
  const loginError = document.getElementById('login-error');
  const btnCerrarSesion = document.getElementById('btn-cerrar-sesion');

  const navBtns = document.querySelectorAll('.nav-btn');
  const tabs = document.querySelectorAll('.tab-content');

  const inputBusqueda = document.getElementById('input-busqueda');
  const filterBtns = document.querySelectorAll('.filter-btn');
  const btnEliminarMasivo = document.getElementById('btn-eliminar-masivo');
  const countSeleccionados = document.getElementById('count-seleccionados');
  const btnLimpiarInactivos = document.getElementById('btn-limpiar-inactivos');
  const chkSelectAll = document.getElementById('chk-select-all');

  const tablaBody = document.querySelector('#tabla-dispositivos tbody');
  const emptyDispositivos = document.getElementById('empty-dispositivos');
  const statTotal = document.getElementById('stat-total');
  const statOnline = document.getElementById('stat-online');
  const statWarning = document.getElementById('stat-warning');
  const statOffline = document.getElementById('stat-offline');

  const contenedorAlertas = document.getElementById('contenedor-alertas');
  const emptyAlertas = document.getElementById('empty-alertas');
  const badgeAlertas = document.getElementById('badge-alertas');

  const gridEstado = document.getElementById('grid-estado');
  const emptyEstado = document.getElementById('empty-estado');

  const btnNuevo = document.getElementById('btn-nuevo');
  const btnNuevoEmpty = document.getElementById('btn-nuevo-empty');
  const btnDescubrir = document.getElementById('btn-descubrir');
  const btnReemplazar = document.getElementById('btn-reemplazar');
  const btnEliminar = document.getElementById('btn-eliminar');
  const btnPing = document.getElementById('btn-ping');
  const btnRefrescarMetricos = document.getElementById('btn-refrescar-metricos');
  const btnLimpiarAlertas = document.getElementById('btn-limpiar-alertas');

  const modal = document.getElementById('modal-form');
  const modalTitulo = document.getElementById('modal-titulo');
  const form = document.getElementById('form-dispositivo');
  const dispIndex = document.getElementById('disp-index');
  const txtNombre = document.getElementById('txt-nombre');
  const txtTipo = document.getElementById('txt-tipo');
  const txtIp = document.getElementById('txt-ip');
  const txtCpu = document.getElementById('txt-cpu');
  const txtRam = document.getElementById('txt-ram');
  const txtTemp = document.getElementById('txt-temp');
  const txtUptime = document.getElementById('txt-uptime');
  const txtEstado = document.getElementById('txt-estado');
  const btnEscanear = document.getElementById('btn-escanear');
  const btnCancelar = document.getElementById('btn-cancelar');

  const toast = document.getElementById('toast');
  const reloj = document.getElementById('reloj');

  // ---------- Cliente API ----------
  async function apiFetch(path, opciones = {}) {
    const token = localStorage.getItem(TOKEN_KEY);
    const headers = Object.assign(
      { 'Content-Type': 'application/json' },
      opciones.headers || {},
      token ? { Authorization: 'Bearer ' + token } : {}
    );
    const respuesta = await fetch(API_BASE + path, { ...opciones, headers });
    if (respuesta.status === 401) {
      cerrarSesion('Tu sesión expiró. Inicia sesión de nuevo.');
      throw new Error('No autenticado');
    }
    return respuesta;
  }

  // ---------- Login / sesión ----------
  async function iniciarSesion() {
    const usuario = loginUsuario.value.trim();
    const password = loginPassword.value;
    loginError.classList.add('hidden');

    if (!usuario || !password) {
      loginError.textContent = 'Ingresa usuario y contraseña.';
      loginError.classList.remove('hidden');
      return;
    }

    btnEmpezar.disabled = true;
    const textoOriginal = btnEmpezar.innerHTML;
    btnEmpezar.textContent = 'Ingresando...';

    try {
      const respuesta = await fetch(API_BASE + '/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usuario, password }),
      });
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'No se pudo iniciar sesión');

      localStorage.setItem(TOKEN_KEY, datos.token);
      loginPassword.value = '';
      entrarAlPanel();
    } catch (e) {
      loginError.textContent = e.message;
      loginError.classList.remove('hidden');
    } finally {
      btnEmpezar.disabled = false;
      btnEmpezar.innerHTML = textoOriginal;
    }
  }

  btnEmpezar.addEventListener('click', iniciarSesion);
  loginPassword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') iniciarSesion();
  });

  function entrarAlPanel() {
    pantallaBienvenida.classList.add('hidden');
    panelPrincipal.classList.remove('hidden');
    cargarTodo();
    if (intervaloActualizacion) clearInterval(intervaloActualizacion);
    intervaloActualizacion = setInterval(cargarTodo, 20000);
  }

  function cerrarSesion(mensaje) {
    localStorage.removeItem(TOKEN_KEY);
    if (intervaloActualizacion) clearInterval(intervaloActualizacion);
    panelPrincipal.classList.add('hidden');
    pantallaBienvenida.classList.remove('hidden');
    if (mensaje) {
      loginError.textContent = mensaje;
      loginError.classList.remove('hidden');
    }
  }

  btnCerrarSesion.addEventListener('click', () => cerrarSesion());

  if (localStorage.getItem(TOKEN_KEY)) {
    entrarAlPanel();
  }

  // ---------- Navegación ----------
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.target;
      tabs.forEach(t => t.classList.toggle('active', t.id === target));
      if (target === 'sec-alertas') {
        alertasNoLeidas = 0;
        actualizarBadgeAlertas();
      }
      if (target === 'sec-estado') {
        cargarEstadisticasNetflow();
      }
    });
  });

  // ---------- Reloj ----------
  function actualizarReloj() {
    reloj.textContent = new Date().toLocaleTimeString('es-MX');
  }
  setInterval(actualizarReloj, 1000);
  actualizarReloj();

  // ---------- Toast ----------
  let toastTimeout;
  function mostrarToast(mensaje) {
    toast.textContent = mensaje;
    toast.classList.remove('hidden');
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => toast.classList.add('hidden'), 2600);
  }

  // ---------- Carga de datos reales ----------
  async function cargarTodo() {
    await Promise.all([
      cargarDispositivos(),
      cargarAlertas(),
      cargarEstadisticasNetflow()
    ]);
  }

  async function cargarDispositivos() {
    try {
      const respuesta = await apiFetch('/api/dispositivos');
      if (!respuesta.ok) throw new Error('No se pudieron cargar los dispositivos');
      dispositivos = await respuesta.json();

      // Limpiar IDs seleccionados que ya no existan en la lista devuelta
      const idsActuales = new Set(dispositivos.map(d => d.id));
      idsSeleccionados = new Set([...idsSeleccionados].filter(id => idsActuales.has(id)));

      renderTabla();
      renderMetricas();
    } catch (e) {
      if (e.message !== 'No autenticado') mostrarToast(e.message);
    }
  }

  async function cargarAlertas() {
    try {
      const respuesta = await apiFetch('/api/alertas');
      if (!respuesta.ok) throw new Error('No se pudieron cargar las alertas');
      const lista = await respuesta.json();

      if (lista.length > ultimoConteoAlertas) {
        const estaEnAlertas = document.getElementById('sec-alertas').classList.contains('active');
        if (!estaEnAlertas) {
          alertasNoLeidas += lista.length - ultimoConteoAlertas;
          actualizarBadgeAlertas();
        }
      }
      ultimoConteoAlertas = lista.length;

      alertas = lista.map(a => ({
        severidad: mapSeveridad(a.severidad),
        titulo: a.mensaje,
        descripcion: a.origen ? `Origen: ${a.origen}` : '',
        hora: new Date(a.creada_en).toLocaleTimeString('es-MX'),
      }));
      renderAlertas();
    } catch (e) {
      if (e.message !== 'No autenticado') console.error(e);
    }
  }

  // ---------- Búsqueda y Filtros de dispositivos ----------
  if (inputBusqueda) {
    inputBusqueda.addEventListener('input', (e) => {
      textoBusqueda = e.target.value.trim();
      renderTabla();
    });
  }

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filtroEstado = btn.dataset.filter;
      renderTabla();
    });
  });

  // ---------- Render: tabla de dispositivos ----------
  function obtenerDispositivosFiltrados() {
    return dispositivos.filter(d => {
      const cumpleEstado = filtroEstado === 'todos' || d.estado === filtroEstado;
      const q = textoBusqueda.toLowerCase();
      const cumpleBusqueda = !q ||
        d.nombre.toLowerCase().includes(q) ||
        d.ip.toLowerCase().includes(q) ||
        d.tipo.toLowerCase().includes(q);
      return cumpleEstado && cumpleBusqueda;
    });
  }

  function badgeTipoDispositivo(tipo) {
    const t = (tipo || '').toLowerCase();
    let icono = '💻';
    let clase = 'type-pc';

    if (t.includes('router') || t.includes('gateway')) {
      icono = '🌐';
      clase = 'type-router';
    } else if (t.includes('switch')) {
      icono = '🔌';
      clase = 'type-switch';
    } else if (t.includes('servidor') || t.includes('server')) {
      icono = '🖥️';
      clase = 'type-servidor';
    } else if (t.includes('impresora') || t.includes('printer')) {
      icono = '🖨️';
      clase = 'type-impresora';
    } else if (t.includes('cámara') || t.includes('camara') || t.includes('camera')) {
      icono = '📹';
      clase = 'type-camara';
    }

    return `<span class="type-badge ${clase}">${icono} ${escapeHtml(tipo)}</span>`;
  }

  function renderTabla() {
    tablaBody.innerHTML = '';
    const filtrados = obtenerDispositivosFiltrados();

    emptyDispositivos.classList.toggle('hidden', filtrados.length > 0);

    if (chkSelectAll) {
      chkSelectAll.checked = filtrados.length > 0 && filtrados.every(d => idsSeleccionados.has(d.id));
    }

    filtrados.forEach(d => {
      const tr = document.createElement('tr');
      tr.dataset.id = d.id;
      const estaSeleccionado = idsSeleccionados.has(d.id);
      if (estaSeleccionado) tr.classList.add('selected');

      tr.innerHTML = `
        <td class="col-select" style="text-align:center;">
          <input type="checkbox" class="chk-row" data-id="${d.id}" ${estaSeleccionado ? 'checked' : ''}>
        </td>
        <td><strong>${escapeHtml(d.nombre)}</strong></td>
        <td>${badgeTipoDispositivo(d.tipo)}</td>
        <td class="ip-cell">${escapeHtml(d.ip)}</td>
        <td>
          <span class="status-pill ${claseEstado(d.estado)}">
            <span class="pulse-dot small ${d.estado === 'online' ? '' : d.estado}"></span>
            ${textoEstado(d.estado)}
          </span>
        </td>
      `;

      const chk = tr.querySelector('.chk-row');
      chk.addEventListener('click', (e) => {
        e.stopPropagation();
        if (chk.checked) idsSeleccionados.add(d.id);
        else idsSeleccionados.delete(d.id);
        actualizarAccionesMasivas();
        tr.classList.toggle('selected', chk.checked);
      });

      tr.addEventListener('click', () => {
        if (idsSeleccionados.has(d.id)) {
          idsSeleccionados.delete(d.id);
          chk.checked = false;
        } else {
          idsSeleccionados.add(d.id);
          chk.checked = true;
        }
        actualizarAccionesMasivas();
        tr.classList.toggle('selected', chk.checked);
      });

      tablaBody.appendChild(tr);
    });

    actualizarStats();
    actualizarAccionesMasivas();
  }

  if (chkSelectAll) {
    chkSelectAll.addEventListener('change', (e) => {
      const filtrados = obtenerDispositivosFiltrados();
      if (e.target.checked) {
        filtrados.forEach(d => idsSeleccionados.add(d.id));
      } else {
        filtrados.forEach(d => idsSeleccionados.delete(d.id));
      }
      renderTabla();
    });
  }

  function actualizarAccionesMasivas() {
    const cant = idsSeleccionados.size;
    if (countSeleccionados) countSeleccionados.textContent = cant;
    if (btnEliminarMasivo) btnEliminarMasivo.disabled = cant === 0;

    // Acción para editar individualmente la primera fila seleccionada
    seleccionIndex = cant === 1 ? dispositivos.findIndex(d => idsSeleccionados.has(d.id)) : null;
    btnReemplazar.disabled = seleccionIndex === null;
    btnEliminar.disabled = cant === 0;
  }

  function actualizarStats() {
    statTotal.textContent = dispositivos.length;
    statOnline.textContent = dispositivos.filter(d => d.estado === 'online').length;
    statWarning.textContent = dispositivos.filter(d => d.estado === 'warning').length;
    statOffline.textContent = dispositivos.filter(d => d.estado === 'offline').length;
  }

  // ---------- Eliminación masiva e inactivos ----------
  if (btnEliminarMasivo) {
    btnEliminarMasivo.addEventListener('click', async () => {
      const cant = idsSeleccionados.size;
      if (cant === 0) return;

      if (!confirm(`¿Estás seguro de eliminar los ${cant} dispositivo(s) seleccionados del monitoreo?`)) return;

      try {
        const ids = Array.from(idsSeleccionados);
        const respuesta = await apiFetch('/api/dispositivos/eliminar-masivo', {
          method: 'POST',
          body: JSON.stringify({ ids }),
        });
        const datos = await respuesta.json();
        if (!respuesta.ok) throw new Error(datos.error || 'No se pudieron eliminar los dispositivos');

        idsSeleccionados.clear();
        mostrarToast(datos.mensaje || `Se eliminaron ${cant} dispositivos`);
        await cargarDispositivos();
      } catch (e) {
        mostrarToast(e.message);
      }
    });
  }

  if (btnLimpiarInactivos) {
    btnLimpiarInactivos.addEventListener('click', async () => {
      const offlineCount = dispositivos.filter(d => d.estado === 'offline').length;
      if (offlineCount === 0) {
        mostrarToast('No hay dispositivos inactivos (Offline) para limpiar');
        return;
      }

      if (!confirm(`¿Eliminar todos los ${offlineCount} dispositivos desconectados (Offline) de la lista?`)) return;

      try {
        const respuesta = await apiFetch('/api/dispositivos/limpiar-inactivos', { method: 'POST' });
        const datos = await respuesta.json();
        if (!respuesta.ok) throw new Error(datos.error || 'No se pudieron limpiar los inactivos');

        idsSeleccionados.clear();
        mostrarToast(datos.mensaje || 'Inactivos eliminados correctamente');
        await cargarDispositivos();
      } catch (e) {
        mostrarToast(e.message);
      }
    });
  }

  // ---------- Render: métricas & NetFlow ----------
  async function cargarEstadisticasNetflow() {
    try {
      const respuesta = await apiFetch('/api/netflow/grafica');
      if (!respuesta.ok) return;
      const datos = await respuesta.json();

      const valEntropia = document.getElementById('val-entropia');
      if (valEntropia) valEntropia.textContent = (datos.entropia_red || 0).toFixed(2);

      const listaTalkers = document.getElementById('lista-top-talkers');
      if (listaTalkers) {
        listaTalkers.innerHTML = '';
        if (datos.top_hosts && datos.top_hosts.length > 0) {
          datos.top_hosts.forEach(h => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="ip">${escapeHtml(h.origen)}</span><span class="flujos">${h.flujos} flujos</span>`;
            listaTalkers.appendChild(li);
          });
        } else {
          listaTalkers.innerHTML = '<li class="empty-text">Sin datos de flujos en la red</li>';
        }
      }

      dibujarGraficaNetflow(datos.serie_tiempo || []);
    } catch (e) {
      if (e.message !== 'No autenticado') console.error('Error al cargar gráfica NetFlow:', e);
    }
  }

  function dibujarGraficaNetflow(puntos) {
    const canvas = document.getElementById('canvas-netflow');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    canvas.width = rect.width * (window.devicePixelRatio || 1);
    canvas.height = rect.height * (window.devicePixelRatio || 1);
    ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

    const w = rect.width;
    const h = rect.height;

    ctx.clearRect(0, 0, w, h);

    if (puntos.length === 0) {
      ctx.fillStyle = '#64748b';
      ctx.font = '13px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Escuchando flujos NetFlow en tiempo real (puerto UDP 2055)...', w / 2, h / 2);
      return;
    }

    const maxVal = Math.max(...puntos.map(p => p.cantidad_flujos), 5);
    const padding = 24;
    const graphW = w - padding * 2;
    const graphH = h - padding * 2;

    // Grid de fondo
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = padding + (graphH / 3) * i;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(w - padding, y);
      ctx.stroke();
    }

    const coords = puntos.map((p, idx) => {
      const x = padding + (idx / Math.max(puntos.length - 1, 1)) * graphW;
      const y = h - padding - (p.cantidad_flujos / maxVal) * graphH;
      return { x, y, hora: p.hora, val: p.cantidad_flujos };
    });

    const grad = ctx.createLinearGradient(0, padding, 0, h - padding);
    grad.addColorStop(0, 'rgba(76, 141, 255, 0.35)');
    grad.addColorStop(1, 'rgba(76, 141, 255, 0.0)');

    ctx.beginPath();
    ctx.moveTo(coords[0].x, h - padding);
    coords.forEach(c => ctx.lineTo(c.x, c.y));
    ctx.lineTo(coords[coords.length - 1].x, h - padding);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    coords.forEach((c, idx) => {
      if (idx === 0) ctx.moveTo(c.x, c.y);
      else ctx.lineTo(c.x, c.y);
    });
    ctx.strokeStyle = '#4C8DFF';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    coords.forEach((c, idx) => {
      ctx.beginPath();
      ctx.arc(c.x, c.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#2ED573';
      ctx.fill();
      ctx.strokeStyle = '#060A12';
      ctx.lineWidth = 2;
      ctx.stroke();

      if (idx % Math.ceil(coords.length / 6) === 0) {
        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        ctx.fillText(c.hora, c.x, h - 4);
      }
    });
  }

  function renderMetricas() {
    gridEstado.innerHTML = '';
    emptyEstado.classList.toggle('hidden', dispositivos.length > 0);

    dispositivos.forEach(d => {
      const card = document.createElement('div');
      card.className = 'metric-card';
      card.innerHTML = `
        <div class="metric-card-head">
          <div>
            <p class="metric-name">${escapeHtml(d.nombre)}</p>
            <span class="metric-ip">${escapeHtml(d.ip)}</span>
          </div>
          <span class="status-pill ${claseEstado(d.estado)}">
            <span class="pulse-dot small ${d.estado === 'online' ? '' : d.estado}"></span>
            ${textoEstado(d.estado)}
          </span>
        </div>
        <div class="gauges-row">
          ${gaugeSvg('CPU', d.cpu_pct, 88)}
          ${gaugeSvg('RAM', d.ram_pct, 92)}
        </div>
        <div class="metric-row"><span>Temperatura</span><span>${d.temp_c != null ? d.temp_c + '°C' : 'N/D'}</span></div>
        <div class="metric-row"><span>Última actualización</span><span>${new Date(d.actualizado_en).toLocaleTimeString('es-MX')}</span></div>
      `;
      gridEstado.appendChild(card);
    });
  }

  function colorMetrica(valor, umbral) {
    if (valor >= umbral) return 'var(--critical)';
    if (valor >= umbral - 20) return 'var(--warning)';
    return 'var(--online)';
  }

  function gaugeSvg(etiqueta, valor, umbral) {
    const r = 32, c = 2 * Math.PI * r;
    const tieneValor = valor !== null && valor !== undefined;
    const val = tieneValor ? Math.min(Math.max(valor, 0), 100) : 0;
    const offset = c - (val / 100) * c;
    const color = tieneValor ? colorMetrica(val, umbral) : 'var(--text-dim)';
    return `
      <div class="gauge">
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle class="gauge-track" cx="40" cy="40" r="${r}"></circle>
          <circle class="gauge-value" cx="40" cy="40" r="${r}"
            style="stroke:${color}; stroke-dasharray:${c}; stroke-dashoffset:${offset};"></circle>
        </svg>
        <span class="gauge-number">${tieneValor ? val + '%' : 'N/D'}</span>
        <div class="gauge-label">${etiqueta}</div>
      </div>
    `;
  }

  // ---------- Render: alertas ----------
  function renderAlertas() {
    contenedorAlertas.innerHTML = '';
    emptyAlertas.classList.toggle('hidden', alertas.length > 0);

    alertas.forEach(a => {
      const div = document.createElement('div');
      div.className = 'alert-card ' + a.severidad;
      div.innerHTML = `
        <div class="alert-icon">${iconoAlerta(a.severidad)}</div>
        <div class="alert-body">
          <p class="alert-title">${escapeHtml(a.titulo)}</p>
          <p class="alert-desc">${escapeHtml(a.descripcion)}</p>
        </div>
        <span class="alert-time">${a.hora}</span>
      `;
      contenedorAlertas.appendChild(div);
    });
  }

  function iconoAlerta(severidad) {
    if (severidad === 'critical') {
      return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><path d="M12 2 1 21h22L12 2Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 9v5M12 17.5v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
    }
    if (severidad === 'warning') {
      return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><path d="M12 8v5M12 16v.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" width="17" height="17" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M12 8h.01M12 11v5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  }

  function actualizarBadgeAlertas() {
    badgeAlertas.textContent = alertasNoLeidas;
    badgeAlertas.classList.toggle('hidden', alertasNoLeidas === 0);
  }

  btnLimpiarAlertas.addEventListener('click', () => {
    alertasNoLeidas = 0;
    actualizarBadgeAlertas();
    mostrarToast('Alertas marcadas como leídas');
  });

  // ---------- Modal: nuevo / editar ----------
  function abrirModal(dispositivo) {
    form.reset();
    txtCpu.value = ''; txtRam.value = ''; txtTemp.value = ''; txtUptime.value = ''; txtEstado.value = '';

    const boxResult = document.getElementById('box-scan-result');
    if (boxResult) {
      boxResult.innerHTML = '';
      boxResult.classList.add('hidden');
    }

    if (dispositivo) {
      modalTitulo.textContent = 'Editar dispositivo';
      dispIndex.value = dispositivo.id;
      txtNombre.value = dispositivo.nombre;
      txtTipo.value = dispositivo.tipo;
      txtIp.value = dispositivo.ip;
      txtEstado.value = textoEstado(dispositivo.estado);
      txtCpu.value = dispositivo.cpu_pct != null ? dispositivo.cpu_pct + '%' : 'N/D';
      txtRam.value = dispositivo.ram_pct != null ? dispositivo.ram_pct + '%' : 'N/D';
      txtTemp.value = dispositivo.temp_c != null ? dispositivo.temp_c + '°C' : 'N/D';
      txtUptime.value = new Date(dispositivo.actualizado_en).toLocaleTimeString('es-MX');
    } else {
      modalTitulo.textContent = 'Nuevo dispositivo';
      dispIndex.value = '';
    }
    modal.classList.remove('hidden');
    txtNombre.focus();
  }

  function cerrarModal() { modal.classList.add('hidden'); }

  btnNuevo.addEventListener('click', () => abrirModal(null));
  btnNuevoEmpty.addEventListener('click', () => abrirModal(null));
  btnReemplazar.addEventListener('click', () => {
    if (seleccionIndex !== null) abrirModal(dispositivos[seleccionIndex]);
  });
  btnCancelar.addEventListener('click', cerrarModal);
  modal.addEventListener('click', (e) => { if (e.target === modal) cerrarModal(); });

  btnEliminar.addEventListener('click', async () => {
    if (idsSeleccionados.size === 0 && seleccionIndex === null) return;

    const ids = idsSeleccionados.size > 0
      ? Array.from(idsSeleccionados)
      : [dispositivos[seleccionIndex].id];

    if (!confirm(`¿Eliminar los ${ids.length} dispositivo(s) seleccionado(s)?`)) return;

    try {
      const respuesta = await apiFetch('/api/dispositivos/eliminar-masivo', {
        method: 'POST',
        body: JSON.stringify({ ids }),
      });
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'No se pudieron eliminar los dispositivos');

      idsSeleccionados.clear();
      seleccionIndex = null;
      btnReemplazar.disabled = true;
      btnEliminar.disabled = true;
      mostrarToast(datos.mensaje || 'Dispositivo(s) eliminado(s)');
      await cargarDispositivos();
    } catch (e) {
      mostrarToast(e.message);
    }
  });

  // ---------- Escaneo real contra el backend (Nmap) ----------
  btnEscanear.addEventListener('click', async () => {
    const ip = txtIp.value.trim();
    if (!ip) {
      mostrarToast('Ingresa una IP antes de escanear');
      return;
    }

    btnEscanear.disabled = true;
    const textoOriginal = btnEscanear.innerHTML;
    btnEscanear.textContent = 'Escaneando con Nmap...';

    try {
      const respuesta = await apiFetch('/api/nmap/escanear', {
        method: 'POST',
        body: JSON.stringify({ host: ip }),
      });
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'El escaneo falló');

      const enLinea = datos.estado_host === 'up';
      txtEstado.value = enLinea ? 'En línea' : 'Desconectado';
      txtCpu.value = 'N/D (requiere SNMP)';
      txtRam.value = 'N/D (requiere SNMP)';
      txtTemp.value = 'N/D (requiere SNMP)';
      txtUptime.value = new Date().toLocaleTimeString('es-MX');

      // Asignar tipo inferido automáticamente al campo Tipo del formulario
      if (datos.tipo_inferido) {
        txtTipo.value = datos.tipo_inferido;
      }

      // Mostrar resumen visual del escaneo Nmap en la caja del modal
      const boxResult = document.getElementById('box-scan-result');
      if (boxResult) {
        const puertos = datos.puertos_abiertos || [];
        const macStr = datos.mac ? ` (MAC: ${escapeHtml(datos.mac)})` : '';
        const vendorStr = datos.vendor ? escapeHtml(datos.vendor) : 'Desconocido';
        const soStr = datos.so_detectado ? escapeHtml(datos.so_detectado) : 'No detectado';

        let puertosHtml = puertos.length > 0
          ? puertos.map(p => `<span class="port-chip">${p.puerto}/${p.protocolo} (${escapeHtml(p.servicio)})</span>`).join(' ')
          : '<span class="empty-ports">Sin puertos abiertos detectados</span>';

        boxResult.innerHTML = `
          <div class="scan-header">
            <span class="scan-title">🔍 Clasificación Automática Nmap:</span>
            ${badgeTipoDispositivo(datos.tipo_inferido || 'Desconocido')}
          </div>
          <div class="scan-details">
            <div><strong>Fabricante:</strong> ${vendorStr}${macStr}</div>
            <div><strong>SO Detectado:</strong> ${soStr}</div>
            <div class="scan-ports"><strong>Puertos Abiertos (${puertos.length}):</strong> <div class="ports-list">${puertosHtml}</div></div>
          </div>
        `;
        boxResult.classList.remove('hidden');
      }

      const puertos = datos.puertos_abiertos || [];
      mostrarToast(
        enLinea
          ? `Identificado como ${datos.tipo_inferido || 'Dispositivo'} (${puertos.length} puerto(s))`
          : 'El dispositivo no respondió al ping'
      );
    } catch (e) {
      mostrarToast(e.message);
    } finally {
      btnEscanear.disabled = false;
      btnEscanear.innerHTML = textoOriginal;
    }
  });

  // ---------- Guardar dispositivo (crear / editar) ----------
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const nombre = txtNombre.value.trim();
    const tipo = txtTipo.value.trim();
    const ip = txtIp.value.trim();
    const id = dispIndex.value;

    try {
      const respuesta = await apiFetch(
        id !== '' ? `/api/dispositivos/${id}` : '/api/dispositivos',
        {
          method: id !== '' ? 'PUT' : 'POST',
          body: JSON.stringify({ nombre, tipo, ip }),
        }
      );
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'No se pudo guardar el dispositivo');

      mostrarToast(id !== '' ? 'Dispositivo actualizado' : 'Dispositivo agregado');
      seleccionIndex = null;
      btnReemplazar.disabled = true;
      btnEliminar.disabled = true;
      cerrarModal();
      await cargarDispositivos();
    } catch (err) {
      mostrarToast(err.message);
    }
  });

  // ---------- Probar conexión (ping real) ----------
  btnPing.addEventListener('click', async () => {
    const objetivo = idsSeleccionados.size > 0
      ? dispositivos.filter(d => idsSeleccionados.has(d.id))
      : (seleccionIndex !== null ? [dispositivos[seleccionIndex]] : dispositivos);

    if (objetivo.length === 0) {
      mostrarToast('No hay dispositivos para probar');
      return;
    }

    btnPing.disabled = true;
    const textoOriginal = btnPing.innerHTML;
    btnPing.innerHTML = 'Enviando ping...';

    try {
      await Promise.all(
        objetivo.map(d =>
          apiFetch(`/api/dispositivos/${d.id}/ping`, { method: 'POST' }).catch(err => {
            console.error(`Ping falló para ${d.nombre}:`, err);
          })
        )
      );
      await cargarTodo();
      mostrarToast(`Ping completado (${objetivo.length} equipo${objetivo.length > 1 ? 's' : ''})`);
    } finally {
      btnPing.disabled = false;
      btnPing.innerHTML = textoOriginal;
    }
  });

  // ---------- Actualizar métricas manualmente ----------
  btnRefrescarMetricos.addEventListener('click', async () => {
    await cargarTodo();
    mostrarToast('Métricas actualizadas');
  });

  // ---------- Descubrimiento automático de red ----------
  btnDescubrir.addEventListener('click', async () => {
    const sugerida = dispositivos.length > 0
      ? sugerirRedDesdeIp(dispositivos[0].ip)
      : sugerirRedDesdeIp(window.location.hostname);
    const red = prompt('Rango de red a escanear (notación CIDR):', sugerida);
    if (!red) return;

    btnDescubrir.disabled = true;
    const textoOriginal = btnDescubrir.innerHTML;
    btnDescubrir.textContent = 'Descubriendo...';

    try {
      const respuesta = await apiFetch('/api/nmap/descubrir', {
        method: 'POST',
        body: JSON.stringify({ red }),
      });
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'No se pudo escanear la red');

      mostrarToast(
        `Red escaneada: ${datos.hosts_detectados} equipo(s) activo(s), ` +
        `${datos.agregados.length} nuevo(s) agregado(s)`
      );
      await cargarDispositivos();
    } catch (e) {
      mostrarToast(e.message);
    } finally {
      btnDescubrir.disabled = false;
      btnDescubrir.innerHTML = textoOriginal;
    }
  });

  function sugerirRedDesdeIp(ip) {
    const partes = (ip || '').split('.');
    if (partes.length !== 4) return '192.168.1.0/24';
    return `${partes[0]}.${partes[1]}.${partes[2]}.0/24`;
  }

})();
