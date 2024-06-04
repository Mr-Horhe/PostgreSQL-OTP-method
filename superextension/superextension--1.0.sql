CREATE OR REPLACE FUNCTION superfunction(IN integer, IN text, IN seed DEFAULT 0, OUT f1 integer, OUT f2 text)  RETURNS SETOF record AS '$libdir/superextension', 'superfunction' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION change_password(user_name text, password_function text) RETURNS void AS $$
DECLARE
    new_password text;
BEGIN
    EXECUTE format('SELECT f2 from %s WHERE f1=1', password_function) INTO new_password;
    EXECUTE format('ALTER USER %I WITH PASSWORD %L', user_name, new_password);
END;
$$ LANGUAGE plpgsql;

INSERT INTO cron.job (schedule, command, nodename, nodeport, database, username)
VALUES ('*/30 * * * *', 'SELECT change_password('uuu', 'superfunction(20, ''AAAaaa999#'')');', 'localhost', 5432, 'mydb', 'uuu');
