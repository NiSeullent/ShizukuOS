/* SPDX-License-Identifier: GPL-2.0-only
 * FreeType module list for the wineport build (FT_CONFIG_MODULES_H): the outline font drivers DirectWrite needs
 * (TrueType/OpenType, CFF, Type 1, CID), their helper modules, the auto-hinter and the two outline renderers.
 * Bitmap-only formats (PCF, BDF, Windows FNT, PFR, Type 42) and the SDF/SVG renderers are not compiled. */
FT_USE_MODULE( FT_Module_Class, autofit_module_class )
FT_USE_MODULE( FT_Driver_ClassRec, tt_driver_class )
FT_USE_MODULE( FT_Driver_ClassRec, t1_driver_class )
FT_USE_MODULE( FT_Driver_ClassRec, cff_driver_class )
FT_USE_MODULE( FT_Driver_ClassRec, t1cid_driver_class )
FT_USE_MODULE( FT_Module_Class, psaux_module_class )
FT_USE_MODULE( FT_Module_Class, psnames_module_class )
FT_USE_MODULE( FT_Module_Class, pshinter_module_class )
FT_USE_MODULE( FT_Module_Class, sfnt_module_class )
FT_USE_MODULE( FT_Renderer_Class, ft_smooth_renderer_class )
FT_USE_MODULE( FT_Renderer_Class, ft_raster1_renderer_class )
