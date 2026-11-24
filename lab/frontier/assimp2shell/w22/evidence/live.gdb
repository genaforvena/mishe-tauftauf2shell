set disable-randomization on
set breakpoint pending on
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/assimp2shell/pins/assimp-6.0.6/code/AssetLib/glTF/glTFImporter.cpp:204
run
set $sc = mScene
printf "SCENE=%p\n", $sc
delete 1
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/assimp2shell/pins/assimp-6.0.6/code/AssetLib/glTF/glTFImporter.cpp:475
continue
printf "PRE begin=%p finish=%p cap=%p\n", meshes._M_impl._M_start, meshes._M_impl._M_finish, meshes._M_impl._M_end_of_storage
next
printf "LIVE nmesh=%u arr=%p ptr0=%p verts0=%u faces0=%u\n", ((aiScene*)$sc)->mNumMeshes, ((aiScene*)$sc)->mMeshes, ((aiScene*)$sc)->mMeshes[0], ((aiScene*)$sc)->mMeshes[0]->mNumVertices, ((aiScene*)$sc)->mMeshes[0]->mNumFaces
quit
