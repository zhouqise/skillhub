package com.iflytek.skillhub.controller.admin;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.controller.BaseApiController;
import com.iflytek.skillhub.dto.*;
import com.iflytek.skillhub.service.AuditRequestContext;
import com.iflytek.skillhub.service.LdapSettingsAppService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/auth/ldap")
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class LdapSettingsController extends BaseApiController {
    private final LdapSettingsAppService service;
    public LdapSettingsController(LdapSettingsAppService service, ApiResponseFactory factory) { super(factory); this.service = service; }
    @GetMapping
    public ApiResponse<LdapSettingsResponse> getLdapSettings() { return ok("response.success.read", service.get()); }
    @PutMapping
    public ApiResponse<LdapSettingsResponse> saveLdapSettings(@Valid @RequestBody LdapSettingsUpdateRequest body,
            @AuthenticationPrincipal PlatformPrincipal principal, HttpServletRequest request) {
        return ok("response.success.updated", service.save(body, principal.userId(), AuditRequestContext.from(request)));
    }
    @PostMapping("/test")
    public ApiResponse<Boolean> testLdapConnection(@Valid @RequestBody LdapSettingsUpdateRequest body,
            @AuthenticationPrincipal PlatformPrincipal principal, HttpServletRequest request) {
        service.test(body, principal.userId(), AuditRequestContext.from(request));
        return ok("response.success.read", true);
    }
}
