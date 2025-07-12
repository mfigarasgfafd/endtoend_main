-Sugerowane Java JDK: 23.0.1

-do projektu w intelij trzeba dodać JavaFX (testowane 23.02 & 24.01)
    -download & unzip javafx SDK
    intellij file --> project structure --> add javafx-sdk-{version}/lib
    -add vm options: run --> edit configurations --> application/maingui  vm options (przykładowy path):
    --module-path "C:\javafx-sdk-23.0.2\lib" --add-modules javafx.controls,javafx.fxml


-zezwolić na wiele instancji dla MainGUI (2 klienty)

-run SecureChatApplication (konsola z database na http://localhost:8080/h2-console)
-na teraz są fixed kontakty, więc jedno okno musi być Bob, a drugie Alice

-powinno działać z zip, ale jeśli nie to clone https://github.com/mfigarasgfafd/endtoend_main )

-dane do konsoli h2 defaultowe - puste hasło, login sa
