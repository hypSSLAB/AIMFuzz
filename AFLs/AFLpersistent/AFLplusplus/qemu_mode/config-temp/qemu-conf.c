#include <security/pam_appl.h>
#include <stdio.h>
int main(void) {
   const char *service_name = "qemu";
   const char *user = "frank";
   const struct pam_conv pam_conv = { 0 };
   pam_handle_t *pamh = NULL;
   pam_start(service_name, user, &pam_conv, &pamh);
   return 0;
}
