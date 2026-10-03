# R8 rules of the release build.
#
# The generated bindings of uniffi call the Rust library through JNA, and JNA
# finds the fields of a Structure, the methods of a Library, and each callback
# by name at run time. R8 sees none of those uses, thus the bindings and JNA
# keep their names and their members.
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }

# JNA names desktop classes that Android does not have.
-dontwarn java.awt.**

# Classes that a library makes from a name at run time keep the constructor
# that it calls: the database of WorkManager, which Room opens, each worker
# that WorkManager starts, and each component registrar of Firebase.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
