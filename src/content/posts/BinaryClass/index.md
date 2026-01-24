---
title: "Binary Classification and Linear Regression: A Comprehensive Analysis"
published: 2022-12-08
description: ""
image: ""
tags:
  - "ai"
category: "Cybersecurity"
draft: false 
lang: "en"
---

**Giới thiệu**  
Trong thế giới học máy, **phân loại nhị phân** (binary classification) là một trong những bài toán kinh điển nhất, xuất hiện trong vô số ứng dụng thực tế như phát hiện spam, chẩn đoán bệnh, hay phân tích tín dụng. Mục tiêu của nó là phân chia dữ liệu thành hai lớp riêng biệt dựa trên các đặc trưng (features). Điều thú vị là, dù khác biệt về mục tiêu, bài toán này lại có mối liên hệ mật thiết với **hồi quy tuyến tính** (linear regression) thông qua các kỹ thuật tối ưu hóa. Bài viết này sẽ giải mã mối quan hệ đó, đồng thời làm rõ cơ chế toán học đằng sau.

<!-- 
### **1. Phân Loại Nhị Phân: Từ Ý Tưởng Đến Siêu Phẳng**

**Bài toán cốt lõi**: Cho một tập dữ liệu với hai lớp (ví dụ: "Bệnh" và "Không bệnh"), ta cần xây dựng một **siêu phẳng** (hyperplane) trong không gian đa chiều để phân tách chúng. Siêu phẳng này được định nghĩa bởi hàm tuyến tính:  
<p class="formula">\( f_{\mathbf{w}}(\mathbf{x}) = \mathbf{w} \cdot \mathbf{x} \),</p>  
trong đó:  
- \( \mathbf{w} \): Vector trọng số (weights), quyết định hướng và khoảng cách của siêu phẳng.  
- \( \mathbf{x} \): Vector đặc trưng đầu vào.  

Hàm **sign** được áp dụng để xác định lớp:  
- $$\( \text{sign}(f_{\mathbf{w}}(\mathbf{x})) = 1 \)$$: Lớp dương (ví dụ: Bệnh).  
- \( \text{sign}(f_{\mathbf{w}}(\mathbf{x})) = -1 \): Lớp âm (ví dụ: Không bệnh).  
- \( f_{\mathbf{w}}(\mathbf{x}) = 0 \): Điểm nằm trên siêu phẳng (ranh giới quyết định).

---

### **2. Thuật Toán Học: Perceptron và Adaline**  
Để tìm \( \mathbf{w} \) tối ưu, hai thuật toán phổ biến được sử dụng:  

**a. Perceptron**  
- **Nguyên lý**: Cập nhật trọng số mỗi khi mô hình phân loại sai.  
- **Công thức cập nhật**:  
  \( \mathbf{w}_{\text{new}} = \mathbf{w}_{\text{old}} + \eta \cdot y_i \cdot \mathbf{x}_i \),  
  với \( \eta \) là tốc độ học (learning rate), \( y_i \) là nhãn thực tế.  

**b. Adaline (Adaptive Linear Neuron)**  
- **Khác biệt**: Thay vì dùng nhãn rời rạc (\( \pm 1 \)), Adaline tối ưu sai số bình phương giữa giá trị dự đoán và giá trị thực.  
- **Hàm mục tiêu**:  
  \( L(\mathbf{w}) = \sum_{i} (y_i - \mathbf{w} \cdot \mathbf{x}_i)^2 \).  

---

### **3. Hàm Loss và Gradient Descent: Trái Tim Của Tối Ưu Hóa**  
Dù sử dụng thuật toán nào, việc đánh giá hiệu suất mô hình đều dựa trên **hàm loss** (hàm tổn thất). Với phân loại nhị phân, hàm **hinge loss** thường được áp dụng:  
<p class="formula">\( L(\mathbf{w}) = \sum_{i} \max(0, 1 - y_i \cdot f_{\mathbf{w}}(\mathbf{x}_i)) \).</p>  

**Gradient Descent** là chìa khóa để tối ưu hàm loss:  
1. Tính đạo hàm riêng của loss theo từng trọng số \( w_j \).  
2. Cập nhật trọng số:  
   \( w_j^{\text{new}} = w_j^{\text{old}} - \eta \cdot \frac{\partial L}{\partial w_j} \).  

**Ví dụ minh họa**:  
Xét hàm \( f(x, y, z) = (x + y) \cdot z \) với \( x = -2 \), \( y = 5 \), \( z = -4 \):  
- Đạo hàm theo \( x \): \( \frac{\partial f}{\partial x} = z = -4 \).  
- Đạo hàm theo \( y \): \( \frac{\partial f}{\partial y} = z = -4 \).  
- Đạo hàm theo \( z \): \( \frac{\partial f}{\partial z} = x + y = 3 \).  
Quá trình này mô phỏng cách tính gradient để điều chỉnh \( \mathbf{w} \) trong mô hình.

---

### **4. Mối Liên Hệ Với Hồi Quy Tuyến Tính**  
Dù phân loại nhị phân và hồi quy tuyến tính có mục tiêu khác biệt (dự đoán nhãn rời rạc vs. giá trị liên tục), chúng chia sẻ chung kỹ thuật tối ưu:  
- **Gradient Descent**: Được dùng để tối ưu hóa cả hai bài toán.  
- **Hàm Chi Phí**: Hồi quy tuyến tính dùng MSE (Mean Squared Error), trong khi phân loại nhị phân dùng hinge loss hoặc cross-entropy.  
- **Tính Chất Hình Học**: Cả hai đều xác định một siêu phẳng tối ưu trong không gian dữ liệu.

---

### **5. Thách Thức và Ứng Dụng Thực Tiễn**  
- **Dữ Liệu Không Phân Tách Tuyến Tính**: Khi hai lớp chồng lấn, mô hình tuyến tính thất bại. Giải pháp là chuyển sang SVM với kernel hoặc mạng neural.  
- **Ứng Dụng**: Từ lọc email đến hệ thống gợi ý sản phẩm, phân loại nhị phân là nền tảng của nhiều hệ thống AI hiện đại.

---

### **Kết Luận**  
Phân loại nhị phân không chỉ là bài toán cơ bản mà còn là ví dụ điển hình về cách toán học và tối ưu hóa được áp dụng trong học máy. Sự tương đồng với hồi quy tuyến tính phản ánh một nguyên lý sâu xa: Dù bài toán là gì, việc tìm kiếm mô hình tối ưu luôn xoay quanh việc **định nghĩa đúng hàm mục tiêu** và **tối ưu hóa hiệu quả**. Hiểu được điều này, chúng ta có thể mở rộng sang các mô hình phức tạp hơn như SVM hay deep learning với nền tảng vững chắc.
 -->
Updating...