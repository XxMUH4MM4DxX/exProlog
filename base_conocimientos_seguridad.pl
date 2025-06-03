% ===============================================
% Sistema Experto: Diagnostico de Seguridad y Rendimiento de Servidores
% ===============================================

:- dynamic hecho/1.

% -----------------------------------------------
% Preguntas asociadas a los hechos
% -----------------------------------------------

preguntar(alta_tasa_intentos_login, 
    '¿El sistema ha identificado un volumen inusualmente alto de intentos de autenticacion en un corto periodo de tiempo (s/n)?').

preguntar(misma_ip_repetida, 
    '¿Se han detectado multiples intentos de acceso desde una misma direccion IP (s/n)?').

preguntar(usuarios_inexistentes_detectados, 
    '¿Se han registrado intentos de autenticacion con nombres de usuario inexistentes (s/n)?').

preguntar(tokens_invalidos, 
    '¿El sistema ha recibido tokens de autenticacion invalidos o malformados (s/n)?').

preguntar(tiempo_respuesta_lento, 
    '¿El servidor esta presentando tiempos de respuesta inusualmente altos (s/n)?').

preguntar(cpu_alta, 
    '¿El uso del CPU se mantiene consistentemente por encima del umbral normal (s/n)?').

preguntar(memoria_alta, 
    '¿El consumo de memoria RAM se encuentra en niveles criticos (s/n)?').

preguntar(usuarios_legitimos_activos, 
    '¿Hay una cantidad elevada de sesiones de usuarios legitimos activas simultaneamente (s/n)?').

% -----------------------------------------------
% Reglas de diagnostico
% -----------------------------------------------

regla(posible_fuerza_bruta, [alta_tasa_intentos_login, misma_ip_repetida, usuarios_inexistentes_detectados]).
regla(posible_ddos, [alta_tasa_intentos_login, tokens_invalidos, tiempo_respuesta_lento]).
regla(posible_sobrecarga_legitima, [cpu_alta, memoria_alta, usuarios_legitimos_activos]).
regla(requiere_escalado, [cpu_alta, memoria_alta, tiempo_respuesta_lento]).
regla(posible_actividad_sigilosa, [tokens_invalidos, usuarios_inexistentes_detectados, tiempo_respuesta_lento]).

% -----------------------------------------------
% Diagnostico completo
% -----------------------------------------------

realizar_diagnostico :-
    retractall(hecho(_)),
    forall(preguntar(Hecho, Pregunta), (
        nl, write(Pregunta), nl,
        read(Respuesta),
        (Respuesta == s -> assertz(hecho(Hecho)) ; true)
    )),
    diagnosticar.

diagnosticar :-
    findall(Nombre, (regla(Nombre, Hechos), cumple_regla(Hechos)), ReglasCumplidas),
    (
        ReglasCumplidas \= [] ->
            nl, write('======================================'), nl,
            write('       RESULTADOS DEL DIAGNOSTICO     '), nl,
            write('======================================'), nl,
            mostrar_diagnosticos(ReglasCumplidas)
        ;
            nl, write('Diagnostico: SIN COINCIDENCIA EXACTA'), nl,
            write('No se detecto una amenaza concluyente. Hechos activados:'), nl,
            listar_hechos_activados,
            sugerencias_parciales
    ).

% -----------------------------------------------
% Verificacion de reglas
% -----------------------------------------------

cumple_regla([]).
cumple_regla([H|T]) :-
    hecho(H),
    cumple_regla(T).

% -----------------------------------------------
% Mostrar diagnosticos
% -----------------------------------------------

mostrar_diagnosticos([]).
mostrar_diagnosticos([Nombre|T]) :-
    mostrar_descripcion(Nombre),
    orientacion(Nombre),
    nl, mostrar_diagnosticos(T).

% -----------------------------------------------
% Descripciones por diagnostico
% -----------------------------------------------

mostrar_descripcion(posible_fuerza_bruta) :-
    nl, write('Diagnostico de seguridad: POSIBLE ATAQUE DE FUERZA BRUTA DETECTADO'), nl,
    write('Descripcion: Multiples intentos fallidos de inicio de sesion desde una IP recurrente con usuarios inexistentes.'), nl.

mostrar_descripcion(posible_ddos) :-
    nl, write('Diagnostico de seguridad: POSIBLE ATAQUE DDoS DETECTADO'), nl,
    write('Descripcion: Actividad sospechosa de acceso masivo que podria indicar un intento de denegacion de servicio.'), nl.

mostrar_descripcion(posible_sobrecarga_legitima) :-
    nl, write('Diagnostico de rendimiento: SOBRECARGA POR USO LEGITIMO'), nl,
    write('Descripcion: Alta demanda de usuarios legitimos podria estar afectando el rendimiento del sistema.'), nl.

mostrar_descripcion(requiere_escalado) :-
    nl, write('Diagnostico de capacidad: EL SISTEMA PODRIA REQUERIR ESCALADO'), nl,
    write('Descripcion: El servidor muestra signos de limitacion de recursos y podria necesitar ampliacion de capacidad.'), nl.

mostrar_descripcion(posible_actividad_sigilosa) :-
    nl, write('Diagnostico de seguridad: POSIBLE ACTIVIDAD SIGILOSA DETECTADA'), nl,
    write('Descripcion: Presencia de patrones que podrian indicar intentos encubiertos de acceso no autorizado.'), nl.

% -----------------------------------------------
% Orientacion basada en el diagnostico
% -----------------------------------------------

orientacion(posible_fuerza_bruta) :-
    write('Recomendacion: Implementar medidas de bloqueo por intentos fallidos, revisar registros y limitar accesos por IP.'), nl.

orientacion(posible_ddos) :-
    write('Recomendacion: Activar mecanismos anti-DDoS, ajustar reglas de firewall y monitorear el trafico en tiempo real.'), nl.

orientacion(posible_sobrecarga_legitima) :-
    write('Recomendacion: Optimizar el rendimiento del sistema y considerar balanceo de carga si la demanda continua creciendo.'), nl.

orientacion(requiere_escalado) :-
    write('Recomendacion: Evaluar aumento de recursos de hardware o migracion a arquitectura escalable en la nube.'), nl.

orientacion(posible_actividad_sigilosa) :-
    write('Recomendacion: Reforzar auditorias de seguridad y establecer alertas para comportamientos anormales.'), nl.

% -----------------------------------------------
% Hechos activados (cuando no hay coincidencia exacta)
% -----------------------------------------------

listar_hechos_activados :-
    forall(hecho(H), (write('- '), write(H), nl)).

% -----------------------------------------------
% Sugerencias generales si no hay diagnostico claro
% -----------------------------------------------

sugerencias_parciales :-
    nl, write('Sugerencia: Aunque no se ha detectado un patron concluyente, se recomienda revisar los registros y mantener vigilancia activa.'), nl.
