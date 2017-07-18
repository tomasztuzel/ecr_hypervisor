/******************************************************************************
 * kernel.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xsm/xsm.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>

#ifndef COMPAT

enum system_state system_state = SYS_STATE_early_boot;

xen_commandline_t saved_cmdline;
static const char __initconst opt_builtin_cmdline[] = CONFIG_CMDLINE;

static void __init assign_integer_param(
    const struct kernel_param *param, uint64_t val)
{
    switch ( param->len )
    {
    case sizeof(uint8_t):
        *(uint8_t *)param->var = val;
        break;
    case sizeof(uint16_t):
        *(uint16_t *)param->var = val;
        break;
    case sizeof(uint32_t):
        *(uint32_t *)param->var = val;
        break;
    case sizeof(uint64_t):
        *(uint64_t *)param->var = val;
        break;
    default:
        BUG();
    }
}

static void __init _cmdline_parse(const char *cmdline)
{
    char opt[128], *optval, *optkey, *q;
    const char *p = cmdline;
    const struct kernel_param *param;
    int bool_assert;

    for ( ; ; )
    {
        /* Skip whitespace. */
        while ( *p == ' ' )
            p++;
        if ( *p == '\0' )
            break;

        /* Grab the next whitespace-delimited option. */
        q = optkey = opt;
        while ( (*p != ' ') && (*p != '\0') )
        {
            if ( (q-opt) < (sizeof(opt)-1) ) /* avoid overflow */
                *q++ = *p;
            p++;
        }
        *q = '\0';

        /* Search for value part of a key=value option. */
        optval = strchr(opt, '=');
        if ( optval != NULL )
        {
            *optval++ = '\0'; /* nul-terminate the option value */
            q = strpbrk(opt, "([{<");
        }
        else
        {
            optval = q;       /* default option value is empty string */
            q = NULL;
        }

        /* Boolean parameters can be inverted with 'no-' prefix. */
        bool_assert = !!strncmp("no-", optkey, 3);
        if ( !bool_assert )
            optkey += 3;

        for ( param = __setup_start; param < __setup_end; param++ )
        {
            if ( strcmp(param->name, optkey) )
            {
                if ( param->type == OPT_CUSTOM && q &&
                     strlen(param->name) == q + 1 - opt &&
                     !strncmp(param->name, opt, q + 1 - opt) )
                {
                    optval[-1] = '=';
                    ((void (*)(const char *))param->var)(q);
                    optval[-1] = '\0';
                }
                continue;
            }

            switch ( param->type )
            {
            case OPT_STR:
                strlcpy(param->var, optval, param->len);
                break;
            case OPT_UINT:
                assign_integer_param(
                    param,
                    simple_strtoll(optval, NULL, 0));
                break;
            case OPT_BOOL:
                if ( !parse_bool(optval) )
                    bool_assert = !bool_assert;
                assign_integer_param(param, bool_assert);
                break;
            case OPT_SIZE:
                assign_integer_param(
                    param,
                    parse_size_and_unit(optval, NULL));
                break;
            case OPT_CUSTOM:
                if ( !bool_assert )
                {
                    if ( *optval )
                        break;
                    safe_strcpy(opt, "no");
                    optval = opt;
                }
                ((void (*)(const char *))param->var)(optval);
                break;
            default:
                BUG();
                break;
            }
        }
    }
}

/**
 *    cmdline_parse -- parses the xen command line.
 * If CONFIG_CMDLINE is set, it would be parsed prior to @cmdline.
 * But if CONFIG_CMDLINE_OVERRIDE is set to y, @cmdline will be ignored.
 */
void __init cmdline_parse(const char *cmdline)
{
    if ( opt_builtin_cmdline[0] )
    {
        printk("Built-in command line: %s\n", opt_builtin_cmdline);
        _cmdline_parse(opt_builtin_cmdline);
    }

#ifndef CONFIG_CMDLINE_OVERRIDE
    if ( cmdline == NULL )
        return;

    safe_strcpy(saved_cmdline, cmdline);
    _cmdline_parse(cmdline);
#endif
}

int __init parse_bool(const char *s)
{
    if ( !strcmp("no", s) ||
         !strcmp("off", s) ||
         !strcmp("false", s) ||
         !strcmp("disable", s) ||
         !strcmp("0", s) )
        return 0;

    if ( !strcmp("yes", s) ||
         !strcmp("on", s) ||
         !strcmp("true", s) ||
         !strcmp("enable", s) ||
         !strcmp("1", s) )
        return 1;

    return -1;
}

unsigned int tainted;

/**
 *      print_tainted - return a string to represent the kernel taint state.
 *
 *  'C' - Console output is synchronous.
 *  'E' - An error (e.g. a machine check exceptions) has been injected.
 *  'H' - HVM forced emulation prefix is permitted.
 *  'M' - Machine had a machine check experience.
 *
 *      The string is overwritten by the next call to print_taint().
 */
char *print_tainted(char *str)
{
    if ( tainted )
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c%c",
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_SYNC_CONSOLE ? 'C' : ' ',
                 tainted & TAINT_ERROR_INJECT ? 'E' : ' ',
                 tainted & TAINT_HVM_FEP ? 'H' : ' ');
    }
    else
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Not tainted");
    }

    return str;
}

void add_taint(unsigned int flag)
{
    tainted |= flag;
}

extern const initcall_t __initcall_start[], __presmp_initcall_end[],
    __initcall_end[];

void __init do_presmp_initcalls(void)
{
    const initcall_t *call;
    for ( call = __initcall_start; call < __presmp_initcall_end; call++ )
        (*call)();
}

void __init do_initcalls(void)
{
    const initcall_t *call;
    for ( call = __presmp_initcall_end; call < __initcall_end; call++ )
        (*call)();
}

# define DO(fn) long do_##fn

#endif

/*
 * Simple hypercalls.
 */

DO(xen_version)(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    bool_t deny = !!xsm_xen_version(XSM_OTHER, cmd);

    switch ( cmd )
    {
    case XENVER_version:
        return (xen_major_version() << 16) | xen_minor_version();

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion;

        memset(extraversion, 0, sizeof(extraversion));
        safe_strcpy(extraversion, deny ? xen_deny() : xen_extra_version());
        if ( copy_to_guest(arg, extraversion, ARRAY_SIZE(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        xen_compile_info_t info;

        memset(&info, 0, sizeof(info));
        safe_strcpy(info.compiler,       deny ? xen_deny() : xen_compiler());
        safe_strcpy(info.compile_by,     deny ? xen_deny() : xen_compile_by());
        safe_strcpy(info.compile_domain, deny ? xen_deny() : xen_compile_domain());
        safe_strcpy(info.compile_date,   deny ? xen_deny() : xen_compile_date());
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;

        memset(info, 0, sizeof(info));
        if ( !deny )
            arch_get_xen_caps(&info);

        if ( copy_to_guest(arg, info, ARRAY_SIZE(info)) )
            return -EFAULT;
        return 0;
    }
    
    case XENVER_platform_parameters:
    {
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };

        if ( copy_to_guest(arg, &params, 1) )
            return -EFAULT;
        return 0;
        
    }
    
    case XENVER_changeset:
    {
        xen_changeset_info_t chgset;

        memset(chgset, 0, sizeof(chgset));
        safe_strcpy(chgset, deny ? xen_deny() : xen_changeset());
        if ( copy_to_guest(arg, chgset, ARRAY_SIZE(chgset)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_get_features:
    {
        xen_feature_info_t fi;
        struct domain *d = current->domain;

        if ( copy_from_guest(&fi, arg, 1) )
            return -EFAULT;

        switch ( fi.submap_idx )
        {
        case 0:
            fi.submap = (1U << XENFEAT_memory_op_vnode_supported);
            if ( VM_ASSIST(d, pae_extended_cr3) )
                fi.submap |= (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( paging_mode_translate(d) )
                fi.submap |= 
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap);
            if ( is_hardware_domain(d) )
                fi.submap |= 1U << XENFEAT_dom0;
#ifdef CONFIG_X86
            switch ( d->guest_type )
            {
            case guest_type_pv:
                fi.submap |= (1U << XENFEAT_mmu_pt_update_preserve_ad) |
                             (1U << XENFEAT_highmem_assist) |
                             (1U << XENFEAT_gnttab_map_avail_bits);
                break;
            case guest_type_hvm:
                fi.submap |= (1U << XENFEAT_hvm_safe_pvclock) |
                             (1U << XENFEAT_hvm_callback_vector) |
                             (has_pirq(d) ? (1U << XENFEAT_hvm_pirqs) : 0);
                break;
            }
#endif
            break;
        default:
            return -EINVAL;
        }

        if ( __copy_to_guest(arg, &fi, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_pagesize:
        if ( deny )
            return 0;
        return (!guest_handle_is_null(arg) ? -EINVAL : PAGE_SIZE);

    case XENVER_guest_handle:
    {
        xen_domain_handle_t hdl;

        if ( deny )
            memset(&hdl, 0, ARRAY_SIZE(hdl));

        BUILD_BUG_ON(ARRAY_SIZE(current->domain->handle) != ARRAY_SIZE(hdl));

        if ( copy_to_guest(arg, deny ? hdl : current->domain->handle,
                           ARRAY_SIZE(hdl) ) )
            return -EFAULT;
        return 0;
    }

    case XENVER_commandline:
    {
        size_t len = ARRAY_SIZE(saved_cmdline);

        if ( deny )
            len = strlen(xen_deny()) + 1;

        if ( copy_to_guest(arg, deny ? xen_deny() : saved_cmdline, len) )
            return -EFAULT;
        return 0;
    }

    case XENVER_build_id:
    {
        xen_build_id_t build_id;
        unsigned int sz;
        int rc;
        const void *p;

        if ( deny )
            return -EPERM;

        /* Only return size. */
        if ( !guest_handle_is_null(arg) )
        {
            if ( copy_from_guest(&build_id, arg, 1) )
                return -EFAULT;

            if ( build_id.len == 0 )
                return -EINVAL;
        }

        rc = xen_build_id(&p, &sz);
        if ( rc )
            return rc;

        if ( guest_handle_is_null(arg) )
            return sz;

        if ( sz > build_id.len )
            return -ENOBUFS;

        if ( copy_to_guest_offset(arg, offsetof(xen_build_id_t, buf), p, sz) )
            return -EFAULT;

        return sz;
    }
    }

    return -ENOSYS;
}

DO(nmi_op)(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xennmi_callback cb;
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;
        rc = register_guest_nmi_callback(cb.handler_address);
        break;
    case XENNMI_unregister_callback:
        rc = unregister_guest_nmi_callback();
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

#ifdef VM_ASSIST_VALID
DO(vm_assist)(unsigned int cmd, unsigned int type)
{
    return vm_assist(current->domain, cmd, type, VM_ASSIST_VALID);
}
#endif

/* Begin Custom hypercalls */
#include <xen/sched.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

DO(vmcs_op)(uint16_t domain_id, unsigned long field, unsigned long value, bool enable)
{
    struct vcpu *vcpu_cur = current;
    struct vcpu *vcpu_cur2;
    long unsigned int val; // XXX Testing
    unsigned int counter = 0;
    // Loop over the current vcpu until we find the domain that we want (domain_id will be the domain that we want)
    if ( vcpu_cur == NULL ) {
        printk("Hypercall-vmcs_op: Current vcpu returned as NULL (1)\n");
        return 1;
    }
    while ( vcpu_cur->domain->next_in_list != NULL ) {
        printk("Hypercall-vmcs_op: vcpu_cur->vcpu_id: %u\n", vcpu_cur->vcpu_id); // XXX Debug
        printk("Hypercall-vmcs_op: vcpu_cur->domain->domain_id: %u\n", vcpu_cur->domain->domain_id); // XXX Debug
        printk("Hypercall-vmcs_op: vcpu_cur->domain->next_in_list->domain_id: %u\n", vcpu_cur->domain->next_in_list->domain_id); // XXX Debug
        printk("Hypercall-vmcs_op: vcpu_cur->domain->next_in_list->max_vcpus: %u\n", vcpu_cur->domain->next_in_list->max_vcpus); // XXX Debug
        vcpu_cur = vcpu_cur->domain->next_in_list->vcpu[0]; // Take a VCPU from the next domain as current
        if (vcpu_cur->domain->domain_id == domain_id ) { // Check if this is the domain that we want
            break;
        }
        counter++;
        if ( counter >= 10 ) { // Return if we expire sufficient attempts. Any more than ten domains seems unlikely.
            printk("Hypercall-vmcs_op: No domain for ID %u found after %d attempts\n", domain_id, counter);
            return 1;
        }
    }
    // At this point, we should have found a VCPU that reflects the domain that we want. Do a sanity check.
    // XXX This is kind of a debug check. Need to fix the logic above.
    if ( vcpu_cur->domain->domain_id != domain_id ) {
        printk("Current VCPU's domain is %u, but we need %u. Aborting.\n", vcpu_cur->domain->domain_id, domain_id);
        return 1;
    }
    // Traverse the VCPU linked list and modify all of of the VCPUs.
    domain_pause( vcpu_cur->domain );
    for_each_vcpu( vcpu_cur->domain, vcpu_cur2 ) {
        __vmptrld(vcpu_cur2->arch.hvm_vmx.vmcs_pa); // Initialize the VMCS for the VCPU
        __vmread(field, &val); // Read the value, to see what it is before we've changed it
        printk("Hypercall-vmcs_op: XXX unsigned long val: %lu\n", val); // XXX Testing
        switch ( field ) {
            case CPU_BASED_VM_EXEC_CONTROL:
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.exec_control); // XXX Debug
                if ( enable ) { // Enable or disable
                    vcpu_cur2->arch.hvm_vmx.exec_control |= value;
                } else {
                    vcpu_cur2->arch.hvm_vmx.exec_control &= ~value;
                }
                __vmwrite(field, vcpu_cur2->arch.hvm_vmx.exec_control);
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.exec_control); // XXX Debug
                break;
            case SECONDARY_VM_EXEC_CONTROL:
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.exec_control); // XXX Debug
                vcpu_cur2->arch.hvm_vmx.exec_control |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
                __vmwrite(CPU_BASED_VM_EXEC_CONTROL, vcpu_cur2->arch.hvm_vmx.exec_control);
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.exec_control); // XXX Debug
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.secondary_exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.secondary_exec_control); // XXX Debug
                vcpu_cur2->arch.hvm_vmx.secondary_exec_control |= value;
                if ( enable ) { // Enable or disable
                    vcpu_cur2->arch.hvm_vmx.secondary_exec_control |= value;
                } else {
                    vcpu_cur2->arch.hvm_vmx.secondary_exec_control &= ~value;
                }
                __vmwrite(field, vcpu_cur2->arch.hvm_vmx.secondary_exec_control);
                printk("Hypercall-vmcs_op: vcpu_cur2->arch.hvm_vmx.secondary_exec_control: %u\n", vcpu_cur2->arch.hvm_vmx.secondary_exec_control); // XXX Debug
                break;
            default:
                printk("Unknown field type\n");
                break;
        }
        __vmread(field, &val); // Read the value, to see what it is after we've changed it
        printk("Hypercall-vmcs_op: XXX unsigned long val: %lu\n", val); // XXX Testing
        printk("Hypercall-vmcs_op: Did __vmptrld, __vmwrite, etc etc on vcpu_id: %d\n", vcpu_cur2->vcpu_id);
    }
    domain_unpause( vcpu_cur->domain );
    printk("Hypercall-vmcs_op: called\n");
    printk("Hypercall-vmcs_op: Inputs (domain_id, field, value): %u, %lu, %lu\n", domain_id, field, value);
    return 1;
}

DO(vmwrite_2)(unsigned int op1, unsigned int op2)
{
    printk("vmwrite_2 called\n");
    printk("Inputs (op1, op2): %u, %u\n", op1, op2);
    return 1;
}

/* End Custom hypercalls */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
