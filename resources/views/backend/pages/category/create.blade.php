@extends('layouts.app')
@section('title')
<title>VTV - Thêm danh mục</title>
@endsection
@section('main')
    <!-- Content Header (Page header) -->
    <section class="content-header">
        <div class="container-fluid">
            <div class="row mb-2">
                <div class="col-sm-6">
                    <h1>Thêm danh mục</h1>
                </div>
                <div class="col-sm-6">
                    <ol class="breadcrumb float-sm-right">
                        <li class="breadcrumb-item"><a href="#">Home</a></li>
                        <li class="breadcrumb-item"><a href="#">Danh mục</a></li>
                        <li class="breadcrumb-item active">Thêm danh mục</li>
                    </ol>
                </div>
            </div>
        </div><!-- /.container-fluid -->
    </section>

    <!-- Main content -->
    <section class="content">
        <div class="container-fluid">
          @if(Session::has('success'))
          <div class="alert alert-info alert-dismissible">
            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
            <h5><i class="icon fas fa-info"></i>{{ Session::get('success') }}</h5>
            
          </div>
        @endif
        @if ($errors->any())
        <div class="alert alert-warning alert-dismissible">
            <ul>
                @foreach ($errors->all() as $error)
                    <li>{{ $error }}</li>
                @endforeach
            </ul>
        </div>
        @endif
                    <div class="card card-primary">
                        <div class="card-header">
                            <h3 class="card-title">Thêm danh mục</h3>
                        </div>
                      
                        <!-- /.card-header -->
                        <!-- form start -->
                        <form method="POST" action="{{ route('danhmuc.store') }}">
                          @csrf
                            <div class="card-body">
                                <div class="form-group">
                                    <label>Tên danh mục</label>
                                    <input type="text" class="form-control" id="title" name="title" 
                                      placeholder="Nhập tên danh mục" onkeyup="ChangeToSlug();">
                                </div>
                                <div class="form-group">
                                  <div class="row">
                                    <div class="col">
                                      <label for="exampleInputPassword1">Slug</label>
                                      <input type="text" class="form-control" id="slug" name="slug"
                                          placeholder="slug">
                                    </div>
                                    <div class="col">
                                      <label for="examleInput">Chủ biên</label>
                                        <select name="chubien" id="" class="form-control">
                                            <option  selected>-- Chọn người duyệt bài -- </option>
                                            @foreach ($user as $u)
                                              <option value="{{ $u->id }}">{{ $u->name }}</option>
                                            @endforeach
                                            
                                        </select>
                                    </div>
                                  </div>
                                    
                                </div>

                            </div>
                            <!-- /.card-body -->

                            <div class="card-footer">
                              <button type="submit" name="submit" class="btn btn-primary">Thêm</button>
                              <button type="submit" name="submit" value="1" class="btn btn-outline-info"><i
                                      class="mdi mdi-save"></i> Lưu và tiếp tục thêm</button>
                          </div>
                        </form>
                    </div>
        </div>
    </section>
    <!-- /.content -->
@endsection
<script>
  function ChangeToSlug()
{
    var title, slug;
 
    //Lấy text từ thẻ input title 
    title = document.getElementById("title").value;
 
    //Đổi chữ hoa thành chữ thường
    slug = title.toLowerCase();
 
    //Đổi ký tự có dấu thành không dấu
    slug = slug.replace(/á|à|ả|ạ|ã|ă|ắ|ằ|ẳ|ẵ|ặ|â|ấ|ầ|ẩ|ẫ|ậ/gi, 'a');
    slug = slug.replace(/é|è|ẻ|ẽ|ẹ|ê|ế|ề|ể|ễ|ệ/gi, 'e');
    slug = slug.replace(/i|í|ì|ỉ|ĩ|ị/gi, 'i');
    slug = slug.replace(/ó|ò|ỏ|õ|ọ|ô|ố|ồ|ổ|ỗ|ộ|ơ|ớ|ờ|ở|ỡ|ợ/gi, 'o');
    slug = slug.replace(/ú|ù|ủ|ũ|ụ|ư|ứ|ừ|ử|ữ|ự/gi, 'u');
    slug = slug.replace(/ý|ỳ|ỷ|ỹ|ỵ/gi, 'y');
    slug = slug.replace(/đ/gi, 'd');
    //Xóa các ký tự đặt biệt
    slug = slug.replace(/\`|\~|\!|\@|\#|\||\$|\%|\^|\&|\*|\(|\)|\+|\=|\,|\.|\/|\?|\>|\<|\'|\"|\:|\;|_/gi, '');
    //Đổi khoảng trắng thành ký tự gạch ngang
    slug = slug.replace(/ /gi, "-");
    //Đổi nhiều ký tự gạch ngang liên tiếp thành 1 ký tự gạch ngang
    //Phòng trường hợp người nhập vào quá nhiều ký tự trắng
    slug = slug.replace(/\-\-\-\-\-/gi, '-');
    slug = slug.replace(/\-\-\-\-/gi, '-');
    slug = slug.replace(/\-\-\-/gi, '-');
    slug = slug.replace(/\-\-/gi, '-');
    //Xóa các ký tự gạch ngang ở đầu và cuối
    slug = '@' + slug + '@';
    slug = slug.replace(/\@\-|\-\@|\@/gi, '');
    //In slug ra textbox có id “slug”
    document.getElementById('slug').value = slug;
}
</script>
