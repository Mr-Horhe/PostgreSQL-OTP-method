CREATE OR REPLACE FUNCTION superfunction(IN integer, IN text, IN integer, OUT f1 integer, OUT f2 text)  RETURNS SETOF record AS '$libdir/superextension', 'superfunction' LANGUAGE C IMMUTABLE STRICT;