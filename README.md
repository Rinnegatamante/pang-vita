# Pang Adventures Vita

<p align="center"><img src="./screenshots/game.png"></p>

This is a wrapper/port of <b>Pang Adventures</b> for the *PS Vita*.

The port works by loading the official Android ARMv7 executables in memory, resolving its imports with native functions and patching it in order to properly run.
By doing so, it's basically as if we emulate a minimalist Android environment in which we run natively the executable as is.

## Changelog

### v1.0

- Initial release.

## Note

This port works only with version v.1.1.0 or earlier of the game. The recent v.1.2.1 is not supported.

## Setup Instructions (For End Users)

In order to properly install the game, you'll have to follow these steps precisely:

- Install [kubridge](https://github.com/TheOfficialFloW/kubridge/releases/) and [FdFix](https://github.com/TheOfficialFloW/FdFix/releases/) by copying `kubridge.skprx` and `fd_fix.skprx` to your taiHEN plugins folder (usually `ux0:tai`) and adding two entries to your `config.txt` under `*KERNEL`:
  
```
  *KERNEL
  ux0:tai/kubridge.skprx
  ux0:tai/fd_fix.skprx
```

**Note** Don't install fd_fix.skprx if you're using rePatch plugin

- **Optional**: Install [PSVshell](https://github.com/Electry/PSVshell/releases) to overclock your device to 500Mhz.
- Install `libshacccg.suprx`, if you don't have it already, by following [this guide](https://samilops2.gitbook.io/vita-troubleshooting-guide/shader-compiler/extract-libshacccg.suprx).
- Obtain your copy of *Pang Adventures* legally for Android in form of an `.apk` file and an `.obb` file. [You can get all the required files directly from your phone](https://stackoverflow.com/questions/11012976/how-do-i-get-the-apk-of-an-installed-app-without-root-access) or by using an apk extractor you can find in the play store.
- Open the apk with your zip explorer and extract the file `libPangAdventures.so` from the `lib/armeabi-v7a` folder to `ux0:data/pang`. 
- Open the obb with your zip explorer and extract all the files inside it in a folder named `obb`.
- Install [Total Commander](https://www.ghisler.com/download.htm) and its [PSARC plugin](http://totalcmd.net/plugring/PSARC.html).
- Launch Total Commander and navigate up to the folder where `obb` folder has been created.
- Right click on `obb` folder; it will turn red.
- Click on File -> Pack.
- Set `psarc` as Compressor and then click on `Configure` button right below.
- Set `PSARC Version` to `1.3`, `Compression` to `ZLIB` and `Ratio` to `0` and press `OK`
- Press `OK` to launch the compression, it will create a file in `C:\obb.psarc`. (If you get an error, manually change the location in the command line string `psarc: DESTINATIONFOLDER\obb.psarc`).
- Transfer `obb.psarc` to `ux0:data/pang`.
- **Optional**: For trophies to be unlockable, install [NoTrpDRM](https://github.com/Rinnegatamante/NoTrpDrm).

## Build Instructions (For Developers)

In order to build the loader, you'll need a [vitasdk](https://github.com/vitasdk) build fully compiled with softfp usage.  
You can find a precompiled version here: https://github.com/vitasdk/buildscripts/actions/runs/1102643776.  
Additionally, you'll need these libraries to be compiled as well with `-mfloat-abi=softfp` added to their CFLAGS:

- [SoLoud](https://github.com/vitasdk/packages/blob/master/soloud/VITABUILD)

- [libmathneon](https://github.com/Rinnegatamante/math-neon)

  - ```bash
    make install
    ```

- [vitaShaRK](https://github.com/Rinnegatamante/vitaShaRK)

  - ```bash
    make install
    ```

- [kubridge](https://github.com/TheOfficialFloW/kubridge)

  - ```bash
    mkdir build && cd build
    cmake .. && make install
    ```

- [vitaGL](https://github.com/Rinnegatamante/vitaGL)

  - ````bash
    make SOFTFP_ABI=1 NO_DEBUG=1 HAVE_GLSL_SUPPORT=1 install
    ````

After all these requirements are met, you can compile the loader with the following commands:

```bash
mkdir build && cd build
cmake .. && make
```

## Credits

- TheFloW for the original .so loader.
- CatoTheYounger for testing the homebrew and providing screenshots.
