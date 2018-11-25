int nsa_spi_flash_init(int dev_idx)
{
#if 0
    uint32_t ControlReg = 0;
    uint32_t StatusReg  = 0;

    //init spi flash 
    XSpi_GetControlReg(dev_idx,&ControlReg, XSP_FLASH_BASE_ADDR);
    ControlReg = CONTROL_REG_START_STATE;
    XSpi_SetControlReg(dev_idx,ControlReg, XSP_FLASH_BASE_ADDR);

    XSpi_GetControlReg(dev_idx,&ControlReg, XSP_FLASH_BASE_ADDR);
    XSpi_GetStatusReg(dev_idx,&StatusReg, XSP_FLASH_BASE_ADDR);
    //check init flash status
    //NSADRV_DEBUG("ControlReg = %x  StatusReg = %x\n",ControlReg,StatusReg);

    /*check flash info */
    if(getFlashId(dev_idx,flash))
    {
        NSADRV_ERROR("init flash getFlashId ERR\n");
        return -EFAULT;
    }

    //exit four addr mode 
    if(writeRegister(dev_idx,flash,EXIT_FOUR_BYTE_ADDR_MODE, 0, 0))
    {
        NSADRV_ERROR("init flash writeRegister ERR\n");
        return -EFAULT;
    }
#endif
    return 0;
}