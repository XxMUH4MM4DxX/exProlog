% listado de peliculas
pelicula(joker, drama, 2019).
pelicula(titanic, romance, 1997).
pelicula(shrek, animacion, 2001).
pelicula(el_padrino, drama, 1972).
pelicula(interestelar, ciencia_ficcion, 2014).
pelicula(la_vida_es_bella, comedia_dramatica, 1997).
pelicula(redemption, drama, 1994).
pelicula(el_rey_leon, animacion, 1994).
pelicula(pulp_fiction, drama, 1994).
pelicula(avatar, ciencia_ficcion, 2009).
pelicula(inception, ciencia_ficcion, 2010).
pelicula(green_book, comedia_dramatica, 2018).
pelicula(the_dark_knight, accion_dramatica, 2008).
pelicula(roma, drama, 2018).

% regla para recomendar pelicula de acuerdo al Genero

recomendar_genero(Pelicula, Genero) :-
    pelicula(Pelicula, Genero, _),
    write('Te recomendamos la pelicula: '), write(Pelicula).