% hechos que representan el arbol
mujer(grisel).
mujer(ambar).
hombre(diego).
hombre(julian).

madre(grisel, diego).
madre(grisel, julian).
madre(grisel, ambar).

% datos sobre empleados 
empleado(juan, 35, ingeniero).
empleado(maria, 28, analista).
empleado(pedro, 40, gerente).


% crear regla para consultar empleados menores a 30 

joven(Persona):- empleado(Persona, Edad, _), Edad < 30.

% Pregunta y respuesta 
saludo_respuesta(Saludo) :-
    member(Saludo, ['Hola', 'Como estas?', 'Buenos dias', 'Que tal?']),
    responder_saludo(Saludo).

% regla auxiliar para responder a saludos específicos
responder_saludo('Hola') :-
    write('Hola En que puedo ayudarte?'), nl.
responder_saludo('Como estas?') :-
    write('Estoy bien, gracias por preguntar.'), nl.
responder_saludo('Buenos dias') :-
    write('Buenos dias, ¿como puedo ayudarte?'), nl.
responder_saludo('Que tal?') :-
    write('Todo bien, y tu?'), nl.
responder_saludo(_) :-
    write('Lo siento, no entendi tu saludo.'), nl.


