package by.csl.kcm;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;

/**
 * Отдаёт установщику Android скачанный APK.
 *
 * Начиная с Android 7 просто передать файл по file:// нельзя — система
 * выбрасывает FileUriExposedException. Обычно для этого берут AndroidX
 * FileProvider, но здесь библиотек нет вообще, поэтому провайдер свой,
 * на 40 строк: он умеет только открыть файл из папки «updates».
 */
public final class UpdateProvider extends ContentProvider {

    static final String AUTHORITY = "by.csl.kcm.updates";

    /** Папка, из которой разрешено отдавать файлы. */
    static File dir(android.content.Context c) {
        File d = new File(c.getFilesDir(), "updates");
        if (!d.exists()) {
            //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        }
        return d;
    }

    static Uri uriFor(String fileName) {
        return Uri.parse("content://" + AUTHORITY + "/" + Uri.encode(fileName));
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        if (getContext() == null) {
            return null;
        }
        String name = uri.getLastPathSegment();
        if (name == null || name.contains("/") || name.contains("..")) {
            return null;
        }
        File f = new File(dir(getContext()), name);
        if (!f.isFile()) {
            return null;
        }
        try {
            return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return "application/vnd.android.package-archive";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
