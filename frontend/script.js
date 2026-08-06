/* ============================================================
   NetPulse — lógica del panel de monitoreo
   Conectado al backend real (Rust/Actix) vía fetch(). Ya no simula
   datos con Math.random(): todo lo que se ve viene de la API.
   ============================================================ */

(function () {
  'use strict';

  // El backend siempre corre en el puerto 8080. En vez de fijar
  // "localhost" a mano, se usa el mismo host desde el que se cargó esta
  // página (window.location.hostname) -- así funciona igual si entras
  // por http://localhost o por la IP de la máquina en la red local
  // (ej. http://192.168.1.50), sin tener que tocar este archivo.
  const API_BASE = window.API_BASE || `http://${window.location.hostname}:8080`;
  const TOKEN_KEY = 'netpulse_token';

  // ---------- Estado de la aplicación (se llena desde el backend) ----------
  let dispositivos = [];
  let alertas = [];
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
    // "Tiempo real" vía polling cada 20s. Para este alcance de proyecto
    // no hace falta WebSockets; si más adelante se necesita push real,
    // este es el punto donde se reemplazaría por una conexión ws.
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

  // Si ya había una sesión guardada (recarga de página), entra directo.
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
    await Promise.all([cargarDispositivos(), cargarAlertas()]);
  }

  async function cargarDispositivos() {
    try {
      const respuesta = await apiFetch('/api/dispositivos');
      if (!respuesta.ok) throw new Error('No se pudieron cargar los dispositivos');
      dispositivos = await respuesta.json();
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

  // ---------- Render: tabla de dispositivos ----------
  function renderTabla() {
    tablaBody.innerHTML = '';
    emptyDispositivos.classList.toggle('hidden', dispositivos.length > 0);

    dispositivos.forEach((d, i) => {
      const tr = document.createElement('tr');
      tr.dataset.index = i;
      if (i === seleccionIndex) tr.classList.add('selected');
      tr.innerHTML = `
        <td class="col-select"><span class="row-radio"></span></td>
        <td>${escapeHtml(d.nombre)}</td>
        <td>${escapeHtml(d.tipo)}</td>
        <td class="ip-cell">${escapeHtml(d.ip)}</td>
        <td>
          <span class="status-pill ${claseEstado(d.estado)}">
            <span class="pulse-dot small ${d.estado === 'online' ? '' : d.estado}"></span>
            ${textoEstado(d.estado)}
          </span>
        </td>
      `;
      tr.addEventListener('click', () => seleccionarFila(i));
      tablaBody.appendChild(tr);
    });

    actualizarStats();
  }

  function seleccionarFila(i) {
    seleccionIndex = (seleccionIndex === i) ? null : i;
    btnReemplazar.disabled = seleccionIndex === null;
    btnEliminar.disabled = seleccionIndex === null;
    renderTabla();
  }

  function actualizarStats() {
    statTotal.textContent = dispositivos.length;
    statOnline.textContent = dispositivos.filter(d => d.estado === 'online').length;
    statWarning.textContent = dispositivos.filter(d => d.estado === 'warning').length;
    statOffline.textContent = dispositivos.filter(d => d.estado === 'offline').length;
  }

  // ---------- Render: métricas ----------
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
    if (seleccionIndex === null) return;
    const d = dispositivos[seleccionIndex];
    if (!confirm(`¿Eliminar "${d.nombre}" (${d.ip}) del monitoreo?`)) return;

    try {
      const respuesta = await apiFetch(`/api/dispositivos/${d.id}`, { method: 'DELETE' });
      if (!respuesta.ok && respuesta.status !== 204) throw new Error('No se pudo eliminar el dispositivo');

      seleccionIndex = null;
      btnReemplazar.disabled = true;
      btnEliminar.disabled = true;
      mostrarToast('Dispositivo eliminado');
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
    btnEscanear.textContent = 'Escaneando...';

    try {
      const respuesta = await apiFetch('/api/nmap/escanear', {
        method: 'POST',
        body: JSON.stringify({ host: ip }),
      });
      const datos = await respuesta.json();
      if (!respuesta.ok) throw new Error(datos.error || 'El escaneo falló');

      const enLinea = datos.estado_host === 'up';
      txtEstado.value = enLinea ? 'En línea' : 'Desconectado';
      // CPU/RAM/Temperatura no salen de un escaneo de puertos -- eso
      // requiere SNMP (ver hint del panel de Métricas).
      txtCpu.value = 'N/D (requiere SNMP)';
      txtRam.value = 'N/D (requiere SNMP)';
      txtTemp.value = 'N/D (requiere SNMP)';
      txtUptime.value = new Date().toLocaleTimeString('es-MX');

      const puertos = datos.puertos_abiertos || [];
      mostrarToast(
        enLinea
          ? `Dispositivo en línea · ${puertos.length} puerto(s) abierto(s)`
          : 'El dispositivo no respondió'
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
    const objetivo = seleccionIndex !== null ? [dispositivos[seleccionIndex]] : dispositivos;
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
      await cargarTodo(); // trae estados nuevos y cualquier alerta generada en el backend
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

  // Si ya hay dispositivos, sugiere la /24 del primero (ej. 192.168.1.5
  // -> 192.168.1.0/24); si no hay ninguno, intenta con el host actual.
  function sugerirRedDesdeIp(ip) {
    const partes = (ip || '').split('.');
    if (partes.length !== 4) return '192.168.1.0/24';
    return `${partes[0]}.${partes[1]}.${partes[2]}.0/24`;
  }

})();
